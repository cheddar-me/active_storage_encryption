# frozen_string_literal: true

# Unlike the AWS SDKs, the Ruby GCP SDKs do not have a built-in resumable upload feature, while that
# feature is well-supported by GCP (and has been supported for a long while). This module provides
# resumable uploads in an IO-like package, giving you an object you can write to.
#
#  file = @bucket.file("upload.bin", skip_lookup: true)
#  upload = ActiveStorageEncryption::ResumableGCSUpload.new(file)
#  upload.stream do |io|
#     io.write("Hello resumable")
#     20.times { io.write(Random.bytes(1.megabyte)) }
#  end
#
# Note that to perform the resumable upload your IAM identity or machine identity must have either
# a correct key for accessing Cloud Storage, or - alternatively - run under a service account
# that is permitted to sign blobs. This maps to the "iam.serviceAccountTokenCreator" role -
# see https://github.com/googleapis/google-cloud-ruby/issues/13307 and https://cloud.google.com/iam/docs/service-account-permissions
class ActiveStorageEncryption::EncryptedGCSService::ResumableUpload
  # AWS recommend 5MB as the default part size for multipart uploads. GCP recommend doing "less requests"
  # in general, and they mandate that all parts except last are a multile of 256*1024. Knowing that we will
  # need to hold a buffer of that size, let's just assume that the 5MB that AWS uses is a good number for part size.
  CHUNK_SIZE_FOR_UPLOADS = 5 * 1024 * 1024

  class UploadStartRefused < StandardError
  end

  # When doing GCP uploads the chunks need to be sized to 256KB increments, and the output
  # that we generate is not guaranteed to be chopped up this way. Also the upload for the last
  # chunk is done slightly different than the preceding chunks. It is convenient to have a
  # way to "chop up" an arbitrary streaming output into evenly sized chunks.
  class ByteChunker
    # @param chunk_size[Integer] the chunk size that all the chunks except the last one must have
    # @delivery_proc the proc that will receive the bytes and the `is_last` boolean to indicate the last chunk
    def initialize(chunk_size: 256 * 1024, &delivery_proc)
      @chunk_size = chunk_size.to_i
      # Use a fixed-capacity String instead of a StringIO since there are some advantages
      # to mutable strings, if a string can be reused this saves memory
      @buf_str = String.new(encoding: Encoding::BINARY, capacity: @chunk_size * 2)
      @delivery_proc = delivery_proc.to_proc
    end

    # Appends data to the buffer. Once the size of the chunk has been exceeded, a precisely-sized
    # chunk will be passed to the `delivery_proc`
    #
    # @param bin_str[String] string in binary encoding
    # @return self
    def <<(bin_str)
      @buf_str << bin_str.b
      deliver_buf_in_chunks
      self
    end

    # Appends data to the buffer. Once the size of the chunk has been exceeded, a precisely-sized
    # chunk will be passed to the `delivery_proc`
    #
    # @param bin_str[String] string in binary encoding
    # @return [Integer] number of bytes appended to the buffer
    def write(bin_str)
      self << bin_str
      bin_str.bytesize
    end

    # Sends the last chunk to the `delivery_proc` even if there is nothing output -
    # the last request will usually be needed to close the file
    #
    # @return void
    def finish
      deliver_buf_in_chunks
      @delivery_proc.call(@buf_str, _is_last_chunk = true)
      nil
    end

    private def deliver_buf_in_chunks
      while @buf_str.bytesize > @chunk_size
        @delivery_proc.call(@buf_str[0...@chunk_size], _is_last_chunk = false)
        @buf_str.replace(@buf_str[@chunk_size..])
      end
    end
  end

  # Largely inspired by https://gist.github.com/frankyn/9a5344d1b19ed50ebbf9f15f0ff92032
  # Acts like a writable object that you send data into. The object will split the data
  # you send into chunks and send it to GCP cloud storage, you do not need to indicate
  # the size of the output in advance. You do need to close the object to deliver the
  # last chunk
  class RangedPutIO
    extend Forwardable
    def_delegators :@chunker, :write, :finish, :<<

    # The chunks have to be sized in multiples of 256 kibibytes or 262,144 bytes
    CHUNK_SIZE_UNIT = 256 * 1024

    def initialize(put_url, chunk_size:, content_type: "binary/octet-stream")
      raise ArgumentError, "chunk_size of #{chunk_size} is not a multiple of #{CHUNK_SIZE_UNIT}" unless (chunk_size % CHUNK_SIZE_UNIT).zero?

      @put_uri = URI(put_url)
      @last_byte = 0
      @total_bytes = 0
      @content_type = content_type
      @chunker = ByteChunker.new(chunk_size: chunk_size) { |bytes, is_last| upload_chunk(bytes, is_last) }
    end

    private

    def upload_chunk(chunk, is_last)
      @total_bytes += chunk.bytesize
      content_range = if is_last
        "bytes #{@last_byte}-#{@last_byte + chunk.bytesize - 1}/#{@total_bytes}"
      else
        "bytes #{@last_byte}-#{@last_byte + chunk.bytesize - 1}/*"
      end
      @last_byte += chunk.bytesize

      headers = {
        "Content-Length" => chunk.bytesize.to_s,
        "Content-Range" => content_range,
        "Content-Type" => @content_type,
        "Content-MD5" => Digest::MD5.base64digest(chunk) # This is to early flag bugs like the one mentioned below with httpx
      }

      # Use plain old Net::HTTP here since currently version 1.4.0 of HTTPX (which is used by Faraday in our env) mangles up the file bytes before upload.
      # when passing a File object directly.
      # See https://cheddar-me.slack.com/archives/C01FEPX7PA9/p1739290056637849
      # and https://gitlab.com/os85/httpx/-/issues/338
      put_response = Net::HTTP.put(@put_uri, chunk, headers)

      # This is weird (from https://cloud.google.com/storage/docs/performing-resumable-uploads#resume-upload):
      #   Repeat the above steps for each remaining chunk of data that you want to upload, using the upper
      #   value contained in the Range header of each response to determine where to start each successive
      #   chunk; you should not assume that the server received all bytes sent in any given request.
      # So in theory we must check that the "Range:" header in the response is "bytes=0-{@last_byte + chunk.bytesize - 1}"
      # and we will add that soon.
      #
      # 308 means "intermediate chunk uploaded", 200 means "last chunk uploaded"
      return if [308, 200].include?(put_response.code.to_i)

      raise "The PUT for the resumable upload responded with status #{put_response.code}, headers #{put_response.to_hash.inspect}"
    end
  end

  # @param [Google::Cloud::Storage::File]
  def initialize(file, content_type: "binary/octet-stream", headers: {}, **signed_url_options)
    @file = file
    @content_type = content_type
    @signed_url_options = signed_url_options # url_issuer_and_signer.merge(signed_url_options)
    @resumable_upload_start_headers = headers.to_h
  end

  # @yields writable[IO] an IO-ish object that responds to `#write`
  def stream(&blk)
    headers = {"x-goog-resumable": "start"}.merge(@resumable_upload_start_headers)
    session_start_url = @file.signed_url(method: "POST", content_type: @content_type, headers: headers, **@signed_url_options)
    response = Net::HTTP.post(URI(session_start_url), "", {"content-type" => @content_type, "x-goog-resumable" => "start"})
    unless response.code.to_i == 201
      raise UploadStartRefused, <<~MSG
        Resumable upload start POST responded with #{response.code} instead of 201.
        Body:
        #{response.body}
      MSG
    end

    resumable_upload_session_put_url = response["location"]
    writable = RangedPutIO.new(resumable_upload_session_put_url, content_type: @content_type, chunk_size: CHUNK_SIZE_FOR_UPLOADS)
    yield(writable)
    writable.finish
  end

  private

  # This is gnarly. It is needed to allow service accounts (workload identity) to sign
  # blobs - which is needed to sign a presigned POST URL. The presigned POST URL allows us
  # to initiate a resumable upload.
  #
  # Comes from here:
  # https://github.com/googleapis/google-cloud-ruby/issues/13307#issuecomment-1894546343
  def url_issuer_and_signer
    env = Google::Cloud.env
    if env.compute_engine?
      # Issuer is the service account email that the Signed URL will be signed with
      # and any permission granted in the Signed URL must be granted to the
      # Google Service Account.
      issuer = env.lookup_metadata "instance", "service-accounts/default/email"

      # Create a lambda that accepts the string_to_sign
      signer = lambda do |string_to_sign|
        iam_client = Google::Apis::IamcredentialsV1::IAMCredentialsService.new

        # Get the environment configured authorization
        scopes = ["https://www.googleapis.com/auth/iam"]
        iam_client.authorization = Google::Auth.get_application_default scopes

        request = Google::Apis::IamcredentialsV1::SignBlobRequest.new(
          payload: string_to_sign
        )
        resource = "projects/-/serviceAccounts/#{issuer}"
        response = iam_client.sign_service_account_blob(resource, request)
        response.signed_blob
      end

      {issuer:, signer:}
    else
      {}
    end
  end
end
