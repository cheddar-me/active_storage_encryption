# frozen_string_literal: true

require_relative "../test_helper"

class ServeByteRangeTest < Minitest::Test
  def test_serves_whole_body
    rng = Random.new(Minitest.seed)
    bytes = rng.bytes(474)
    serve_proc = ->(range, io) {
      io.write(bytes[range])
    }

    env = {}
    status, headers, body = ActiveStorageEncryption::ServeByteRange.serve_ranges(env, resource_size: bytes.bytesize, etag: "AbCehZ", resource_content_type: "x-foo/ba", &serve_proc)

    assert_equal 200, status
    assert_equal({"Accept-Ranges" => "bytes", "Content-Length" => "474", "Content-Type" => "x-foo/ba", "ETag" => "\"AbCehZ\""}, headers)

    output = StringIO.new.binmode
    body.each { |chunk| output.write(chunk) }
    assert_equal bytes, output.string
  end

  def test_serves_single_range
    rng = Random.new(Minitest.seed)
    bytes = rng.bytes(474)
    serve_proc = ->(range, io) {
      io.write(bytes[range])
    }

    env = {"HTTP_RANGE" => "bytes=1-2"}
    status, headers, body = ActiveStorageEncryption::ServeByteRange.serve_ranges(env, resource_size: bytes.bytesize, etag: "AbCehZ", resource_content_type: "x-foo/ba", &serve_proc)

    assert_equal 206, status
    assert_equal({"Accept-Ranges" => "bytes", "Content-Length" => "2", "Content-Range" => "bytes 1-2/474", "Content-Type" => "x-foo/ba", "ETag" => "\"AbCehZ\""}, headers)

    output = StringIO.new.binmode
    body.each { |chunk| output.write(chunk) }
    assert_equal bytes[1..2], output.string

    env = {"HTTP_RANGE" => "bytes=319-"}
    status, headers, body = ActiveStorageEncryption::ServeByteRange.serve_ranges(env, resource_size: bytes.bytesize, etag: "AbCehZ", resource_content_type: "x-foo/ba", &serve_proc)

    assert_equal 206, status
    assert_equal({"Accept-Ranges" => "bytes", "Content-Length" => "155", "Content-Range" => "bytes 319-473/474", "Content-Type" => "x-foo/ba", "ETag" => "\"AbCehZ\""}, headers)

    output = StringIO.new.binmode
    body.each { |chunk| output.write(chunk) }
    assert_equal bytes[319..], output.string

    env = {"HTTP_RANGE" => "bytes=0-0"}
    status, headers, body = ActiveStorageEncryption::ServeByteRange.serve_ranges(env, resource_size: bytes.bytesize, etag: "AbCehZ", resource_content_type: "x-foo/ba", &serve_proc)

    assert_equal 206, status
    assert_equal({"Accept-Ranges" => "bytes", "Content-Length" => "1", "Content-Range" => "bytes 0-0/474", "Content-Type" => "x-foo/ba", "ETag" => "\"AbCehZ\""}, headers)

    output = StringIO.new.binmode
    body.each { |chunk| output.write(chunk) }
    assert_equal bytes[0..0], output.string
  end

  def test_serves_single_range_of_same_range_supplied_multiple_times_just_once
    rng = Random.new(Minitest.seed)
    bytes = rng.bytes(474)
    serve_proc = ->(range, io) {
      io.write(bytes[range])
    }

    env = {"HTTP_RANGE" => "bytes=1-2,1-2,1-2,1-2"}
    status, headers, body = ActiveStorageEncryption::ServeByteRange.serve_ranges(env, resource_size: bytes.bytesize, etag: "AbCehZ", resource_content_type: "x-foo/ba", &serve_proc)

    assert_equal 206, status
    assert_equal({"Accept-Ranges" => "bytes", "Content-Length" => "2", "Content-Range" => "bytes 1-2/474", "Content-Type" => "x-foo/ba", "ETag" => "\"AbCehZ\""}, headers)

    output = StringIO.new.binmode
    body.each { |chunk| output.write(chunk) }
    assert_equal bytes[1..2], output.string
  end

  def test_unions_overlapping_ranges
    rng = Random.new(Minitest.seed)
    bytes = rng.bytes(474)
    serve_proc = ->(range, io) {
      io.write(bytes[range])
    }

    env = {"HTTP_RANGE" => "bytes=1-2,2-8,4-9"}
    status, headers, body = ActiveStorageEncryption::ServeByteRange.serve_ranges(env, resource_size: bytes.bytesize, etag: "AbCehZ", resource_content_type: "x-foo/ba", &serve_proc)

    assert_equal 206, status
    assert_equal({"Accept-Ranges" => "bytes", "Content-Length" => "9", "Content-Range" => "bytes 1-9/474", "Content-Type" => "x-foo/ba", "ETag" => "\"AbCehZ\""}, headers)

    output = StringIO.new.binmode
    body.each { |chunk| output.write(chunk) }
    assert_equal bytes[1..9], output.string
  end

  def test_serves_multiple_ranges
    rng = Random.new(Minitest.seed)
    bytes = rng.bytes(474)
    serve_proc = ->(range, io) {
      io.write(bytes[range])
    }

    env = {"HTTP_RANGE" => "bytes=1-2,4-9,472-"}
    status, headers, body = ActiveStorageEncryption::ServeByteRange.serve_ranges(env, resource_size: bytes.bytesize, etag: "AbCehZ", multipart_boundary: "azuleju", resource_content_type: "x-foo/bar", &serve_proc)

    assert_equal 206, status
    assert_equal({"Accept-Ranges" => "bytes", "Content-Length" => "237", "Content-Type" => "multipart/byteranges; boundary=azuleju", "ETag" => "\"AbCehZ\""}, headers)

    reference_lines = [
      "--azuleju",
      "Content-Type: x-foo/bar",
      "Content-Range: bytes 1-2/474",
      "",
      bytes[1..2],
      "--azuleju",
      "Content-Type: x-foo/bar",
      "Content-Range: bytes 4-9/474",
      "",
      bytes[4..9],
      "--azuleju",
      "Content-Type: x-foo/bar",
      "Content-Range: bytes 472-473/474",
      "",
      bytes[472..473],
      "--azuleju--"
    ]

    output = StringIO.new.binmode
    body.each { |chunk| output.write(chunk) }
    lines = output.string.split("\r\n")

    assert_equal reference_lines, lines
  end

  def test_serves_not_modified_with_just_an_if_none_match
    rng = Random.new(Minitest.seed)
    bytes = rng.bytes(474)
    serve_proc = ->(range, io) {
      io.write(bytes[range])
    }

    env = {"HTTP_IF_NONE_MATCH" => "\"woof\""}
    status, headers, _ = ActiveStorageEncryption::ServeByteRange.serve_ranges(env, resource_size: bytes.bytesize, etag: "\"woof\"", resource_content_type: "x-foo/bar", &serve_proc)

    assert_equal 304, status
    assert_equal({"Accept-Ranges" => "bytes", "Content-Length" => "0", "ETag" => "\"woof\""}, headers)
  end

  def test_serves_entire_document_on_if_range_header_mismatch
    rng = Random.new(Minitest.seed)
    bytes = rng.bytes(474)
    serve_proc = ->(range, io) {
      io.write(bytes[range])
    }

    env = {"HTTP_RANGE" => "bytes=1-2,4-9,472-", "HTTP_IF_RANGE" => "\"v2\""}
    status, headers, _ = ActiveStorageEncryption::ServeByteRange.serve_ranges(env, resource_size: bytes.bytesize, etag: "\"v3\"", multipart_boundary: "azuleju", resource_content_type: "x-foo/bar", &serve_proc)

    assert_equal 200, status
    assert_equal({"Accept-Ranges" => "bytes", "Content-Length" => "474", "Content-Type" => "x-foo/bar", "ETag" => "\"v3\""}, headers)
  end

  def test_generates_boundary_for_multiple_ranges
    rng = Random.new(Minitest.seed)
    bytes = rng.bytes(474)
    serve_proc = ->(range, io) {
      io.write(bytes[range])
    }

    env = {"HTTP_RANGE" => "bytes=1-2,4-9,472-"}
    status, headers, _ = ActiveStorageEncryption::ServeByteRange.serve_ranges(env, resource_size: bytes.bytesize, etag: "AbCehZ", &serve_proc)

    assert_equal 206, status
    assert_equal "335", headers["Content-Length"]
    assert headers["Content-Type"].start_with?("multipart/byteranges; boundary=")
  end

  def test_refuses_invalid_range
    rng = Random.new(Minitest.seed)
    bytes = rng.bytes(474)
    serve_proc = ->(range, io) {
      io.write(bytes[range])
    }

    env = {"HTTP_RANGE" => "bytes=474-"}
    status, headers, body = ActiveStorageEncryption::ServeByteRange.serve_ranges(env, resource_size: bytes.bytesize, etag: "AbCehZ", multipart_boundary: "azuleju", resource_content_type: "x-foo/bar", &serve_proc)

    assert_equal 416, status
    assert_equal({"Accept-Ranges" => "bytes", "Content-Length" => "0", "ETag" => "\"AbCehZ\"", "Content-Range" => "bytes */474"}, headers)

    body.each { |chunk| raise "Should never be called" }
  end

  def test_coalesce_ranges
    assert_equal [], ActiveStorageEncryption::ServeByteRange.coalesce_ranges([])

    ranges = [1..1]
    assert_equal [1..1], ActiveStorageEncryption::ServeByteRange.coalesce_ranges(ranges)

    ranges = [0..0, 0..0, 145..900, 1..12, 3..78, 0..8].shuffle(random: Random.new(Minitest.seed))
    assert_equal [0..78, 145..900], ActiveStorageEncryption::ServeByteRange.coalesce_ranges(ranges).sort_by(&:begin)

    ordered_ranges = [14..32, 0..0, 145..900, 5..16, 4..4]
    # Ordering should be maintained (roughly) in the coalesced ranges
    assert_equal [5..32, 0..0, 145..900, 4..4], ActiveStorageEncryption::ServeByteRange.coalesce_ranges(ordered_ranges)
  end
end
