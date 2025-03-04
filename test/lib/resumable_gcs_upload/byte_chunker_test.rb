require "test_helper"

class ActiveStorageEncryption::ResumableGCSUpload::ByteChunkerTest < ActiveSupport::TestCase
  def chunker_class
    ActiveStorageEncryption::ResumableGCSUpload::ByteChunker
  end

  test "outputs chunks with arbitrary chunk size" do
    rng = Random.new(Minitest.seed)

    32.times do
      chunk_size = rng.rand(1..512)

      last_chunk_flags = []
      out_buf = StringIO.new
      out_buf.binmode

      chunker = chunker_class.new(chunk_size:) do |bytes, is_last_chunk|
        out_buf << bytes
        last_chunk_flags << is_last_chunk
      end

      blob = rng.bytes(rng.rand(1..1024))
      read_size = rng.rand(1..222)

      source_buf = StringIO.new(blob)
      while (bytes = source_buf.read(read_size))
        chunker << bytes
      end
      chunker.finish

      assert_equal blob, out_buf.string

      *all_chunks_except_last, last_chunk_flag = last_chunk_flags
      assert_equal [false], all_chunks_except_last.uniq if all_chunks_except_last.any?
      assert_equal true, last_chunk_flag
    end
  end

  test "outputs chunks correctly when last write is at boundary" do
    writes = []
    chunker = chunker_class.new(chunk_size: 3) do |chunk, is_last|
      writes << chunk << is_last
    end

    chunker << "a"
    chunker << "b"
    chunker << "c"
    chunker.finish

    assert_equal ["abc", true], writes
  end

  test "outputs chunks correctly when multiple chunks are required" do
    writes = []
    chunker = chunker_class.new(chunk_size: 7) do |chunk, is_last|
      writes << chunk << is_last
    end

    ("a".."z").each do |char|
      chunker << char
    end
    chunker.finish

    assert_equal ["abcdefg", false, "hijklmn", false, "opqrstu", false, "vwxyz", true], writes
  end

  test "outputs chunks correctly when all the data is furnished in a single write" do
    writes = []
    chunker = chunker_class.new(chunk_size: 7) do |chunk, is_last|
      writes << chunk << is_last
    end

    chunker << ("a".."z").to_a.join
    chunker.finish

    assert_equal ["abcdefg", false, "hijklmn", false, "opqrstu", false, "vwxyz", true], writes
  end

  test "outputs chunks correctly when only write is below chunk_size" do
    writes = []
    chunker = chunker_class.new(chunk_size: 3) do |chunk, is_last|
      writes << chunk << is_last
    end

    chunker << "a"
    chunker.finish

    assert_equal ["a", true], writes
  end

  test "outputs a single zero-sized last chunk when finishing with a write of a few empty strings" do
    writes = []
    chunker = chunker_class.new(chunk_size: 3) do |chunk, is_last|
      writes << chunk << is_last
    end
    chunker << "" << ""
    chunker.finish

    assert_equal ["", true], writes
  end

  test "outputs a single zero-sized last chunk when finishing without writes" do
    writes = []
    chunker = chunker_class.new(chunk_size: 3) do |chunk, is_last|
      writes << chunk << is_last
    end
    chunker.finish

    assert_equal ["", true], writes
  end
end
