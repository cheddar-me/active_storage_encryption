# frozen_string_literal: true

module ActiveStorageEncryption::ServeByteRange
  class BlockWritableWithLimit
    def initialize(limit, &block_that_accepts_writes)
      @limit = limit
      @written = 0
      @block_that_accepts_bytes = block_that_accepts_writes
    end

    def write(string)
      return 0 if string.empty?
      would_have_output = @written + string.bytesize
      raise "You are trying to write more than advertised - #{would_have_output} bytes, the limit for this range is #{@limit}" if @limit < would_have_output
      @written += string.bytesize
      @block_that_accepts_bytes.call(string.b)
      string.bytesize
    end

    def verify!
      raise "You wrote #{@written} bytes but the range requires #{@limit} bytes" unless @written == @limit
    end
  end

  class ByteRangeBody
    def initialize(http_range:, resource_size:, resource_content_type: "binary/octet-stream", &serving_block)
      @http_range = http_range
      @resource_size = resource_size
      @resource_content_type = resource_content_type
      @serving_block = serving_block
    end

    def status
      206
    end

    def each(&blk)
      writable_for_range_bytes = BlockWritableWithLimit.new(@http_range.size, &blk)
      @serving_block.call(@http_range, writable_for_range_bytes)
      writable_for_range_bytes.verify!
    end

    def content_length
      @http_range.size
    end

    def content_type
      @resource_content_type
    end

    def headers
      {
        "Accept-Ranges" => "bytes",
        "Content-Length" => content_length.to_s,
        "Content-Type" => content_type,
        "Content-Range" => "bytes %d-%d/%d" % [@http_range.begin, @http_range.end, @resource_size]
      }
    end
  end

  class EmptyBody
    def status
      200
    end

    def content_length
      0
    end

    def each(&blk)
      # write nothing
    end

    def headers
      {
        "Accept-Ranges" => "bytes",
        "Content-Length" => content_length.to_s
      }
    end
  end

  class WholeBody < ByteRangeBody
    def initialize(resource_size:, **more, &serving_block)
      super(http_range: Range.new(0, resource_size - 1), resource_size: resource_size, **more, &serving_block)
    end

    def status
      200
    end

    def headers
      super.tap { |hh| hh.delete("Content-Range") }
    end
  end

  class Unsatisfiable < EmptyBody
    def initialize(resource_size:)
      @resource_size = resource_size
    end

    def status
      416
    end

    def headers
      super.tap do |hh|
        hh["Content-Range"] = "bytes */%s" % @resource_size
      end
    end
  end

  # See https://www.ietf.org/archive/id/draft-ietf-httpbis-p5-range-09.html
  class MultipartByteRangesBody < ByteRangeBody
    # @param http_ranges[Array<Range>]
    def initialize(http_ranges:, boundary:, **params_for_single_range, &serving_block)
      super(http_range: http_ranges.first, **params_for_single_range)
      @http_ranges = http_ranges
      @boundary = boundary
    end

    def each(&blk)
      @http_ranges.each_with_index do |range, part_i|
        yield(part_header(range, part_i))
        writable_for_range_bytes = BlockWritableWithLimit.new(range.size, &blk)
        @serving_block.call(range, writable_for_range_bytes)
        writable_for_range_bytes.verify!
      end
      yield(trailer)
    end

    def content_length
      # The Content-Length of a multipart response includes the length
      # of all the ranges of the resource, but also the lengths of the
      # multipart part headers - which we need to precompute. To do it
      # we need to run through all of our ranges and output some strings,
      # and if a lot of ranges are involved this can get expensive. So
      # memoize the envelope size (it never changes between calls)
      @envelope_size ||= compute_envelope_size
    end

    def content_type
      "multipart/byteranges; boundary=#{@boundary}"
    end

    def headers
      super.tap do |hh|
        hh.delete("Content-Range")
      end
    end

    private

    def compute_envelope_size
      @http_ranges.each_with_index.inject(0) do |size_sum, (http_range, part_index)|
        # Generate the header for this multipart part ahead of time - we can do this
        # since we know the boundary and can generate the part headers, without retrieving
        # the actual bytes of the resource
        header_bytes = part_header(http_range, part_index)
        # The amount of output contributed by the part is:
        # size of the header for the part + bytes of the part itself
        part_size = header_bytes.bytesize + http_range.size
        size_sum + part_size
      end + trailer.bytesize # Account for the trailer as well
    end

    def trailer
      "\r\n--%s--\r\n" % @boundary
    end

    def part_header(http_range, part_index)
      [
        (part_index > 0) ? "\r\n" : "", # Parts follwing the first have to be delimited "at the top"
        "--%s\r\n" % @boundary,
        "Content-Type: #{@resource_content_type}\r\n",
        "Content-Range: bytes %d-%d/%d\r\n" % [http_range.begin, http_range.end, @resource_size],
        "\r\n"
      ].join
    end
  end

  # Strictly - the boundary is supposed to not appear in any of the parts of the multipart response, so _first_
  # you need to scan the response, pick a byte sequence that does not occur in it, and then use that. In practice,
  # nobody does that - and a well-behaved HTTP client should honor the Content-Range header when extracting
  # the byte range from the response. See https://stackoverflow.com/questions/37413715
  def self.generate_boundary
    Random.bytes(12).unpack1("H*")
  end

  # The RFC specifically gives an example of non-canonical, but still
  # valid request for overlapping ranges:
  #   > Several legal but not canonical specifications of the second 500
  #   > bytes (byte offsets 500-999, inclusive):
  #   >  bytes=500-600,601-999
  #   >  bytes=500-700,601-999
  # In such cases, ranges need to be collapsed together. First, to avoid serving
  # a tiny byte range over and over - causing excessive requests to upstream,
  # second - to optimize for doing less requests in total.
  #
  # @param ranges[Array<Range>] an array of inclusive, limited ranges of integers
  # @return [Array] ranges squashed together honoring their overlaps
  def self.coalesce_ranges(ranges)
    return [] if ranges.empty?
    # The RFC says https://www.rfc-editor.org/rfc/rfc7233#section-6.1
    #
    # > Servers ought to ignore, coalesce, or reject
    # > egregious range requests, such as requests for more than two
    # > overlapping ranges or for many small ranges in a single set,
    # > particularly when the ranges are requested out of order for no
    # > apparent reason.
    sorted_ranges = ranges.sort_by(&:begin)
    first = sorted_ranges.shift
    coalesced_sorted_ranges = sorted_ranges.each_with_object([first]) do |next_range, acc|
      prev_range = acc.pop
      if prev_range.end >= next_range.begin # Range#overlap? can be used on 3.3+
        new_begin = [prev_range.begin, next_range.begin].min
        new_end = [prev_range.end, next_range.end].max
        acc << Range.new(new_begin, new_end)
      else
        acc << prev_range << next_range
      end
    end
    # Sort the ranges according to the order the client requested.
    # The spec says that a client _may_ want to get a certain byte range first,
    # and it seems a legitimate use case, not ill intent.
    #
    # > A client that is requesting multiple ranges SHOULD list those ranges
    # > in ascending order (the order in which they would typically be
    # > received in a complete representation) unless there is a specific
    # > need to request a later part earlier.  For example, a user agent
    # > processing a large representation with an internal catalog of parts
    # > might need to request later parts first, particularly if the
    # > representation consists of pages stored in reverse order and the user
    # > agent wishes to transfer one page at a time.
    indices = ranges.map do |r|
      coalesced_sorted_ranges.find_index { |cr| cr.begin <= r.begin && cr.end >= r.end }
    end
    indices.uniq.map { |i| coalesced_sorted_ranges.fetch(i) }
  end

  # @yield [range, io] The HTTP range being requested and the IO to `write()` the bytes into
  # @example
  #     status, headers, body = serve_ranges(env, resource_size: file.size) do |range, io|
  #       file.seek(range.begin)
  #       IO.copy_stream(file, io, range.size)
  #     end
  #     [status, headers, body]
  # @return [Array] the Rack response triplet of `[status, header_hash, enumerable_body]`
  def self.serve_ranges(env, resource_size:, etag: nil, resource_content_type: "binary/octet-stream", multipart_boundary: generate_boundary, &range_serving_block)
    # As per RFC:
    # If the entity tag given in the If-Range header matches the current cache validator for the entity,
    # then the server SHOULD provide the specified sub-range of the entity using a 206 (Partial Content)
    # response. If the cache validator does not match, then the server SHOULD return the entire entity
    # using a 200 (OK) response.
    wants_ranges_and_etag_valid = env["HTTP_IF_RANGE"] && env["HTTP_IF_RANGE"] == etag && env["HTTP_RANGE"]
    wants_ranges_and_no_etag = !env["HTTP_IF_RANGE"] && env["HTTP_RANGE"]

    # Very old Rack versions do not have get_byte_ranges and have just byte_ranges
    http_ranges_from_header = Rack::Utils.respond_to?(:get_byte_ranges) ? Rack::Utils.get_byte_ranges(env["HTTP_RANGE"], resource_size) : Rack::Utils.byte_ranges(env, resource_size)
    http_ranges_from_header = coalesce_ranges(http_ranges_from_header) if http_ranges_from_header

    body = if resource_size.zero?
      EmptyBody.new
    elsif http_ranges_from_header && (wants_ranges_and_no_etag || wants_ranges_and_etag_valid)
      if http_ranges_from_header.none?
        Unsatisfiable.new(resource_size: resource_size)
      elsif http_ranges_from_header.one?
        ByteRangeBody.new(http_range: http_ranges_from_header.first, resource_size: resource_size, resource_content_type: resource_content_type, &range_serving_block)
      else
        MultipartByteRangesBody.new(http_ranges: http_ranges_from_header, resource_size: resource_size, resource_content_type: resource_content_type, boundary: multipart_boundary, &range_serving_block)
      end
    else
      WholeBody.new(resource_size: resource_size, resource_content_type: resource_content_type, &range_serving_block)
    end
    headers = body.headers

    etag = etag.inspect if etag && !etag.match?(/^".+"$/)
    headers["ETag"] = etag if etag

    [body.status, headers, body]
  end
end
