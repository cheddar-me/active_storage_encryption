module ActiveStorageEncryption::SoftWrapper
  class ServiceWrapperProvidingEncryptionKey < SimpleDelegator
    # Just list out all the methods
    def initialize(service, encryption_key)
      super(service)
      @encryption_key = encryption_key
    end

    # Just enumerate all the methods we override
    [
      :url,
      :upload,
      :download,
      :download_range,
      :headers_for_direct_upload,
      # compose() also needs the keys for the source blobs
    ].each do |method_name|
      define_method(method_name) do |*args, **kwargs, &blk|
        kwargs_with_encryption_key = {encryption_key: @encryption_key}.merge(kwargs)
        super(*args, **kwargs, &blk)
      end
    end

    def inspect
      key_material_instance_variable_names = [:@encryption_key]
      # A reimplementation of #inspect based largely on
      # https://alchemists.io/articles/ruby_object_inspection
      pattern = +""
      values = []

      instance_variables.each do |name|
        pattern << "#{name}=%s "
        ivar_value = instance_variable_get(name)
        if ivar_value.is_a?(String) && key_material_instance_variable_names.include?(name)
          values.push("[SENSITIVE(#{ivar_value.bytesize * 8} bits)]")
        else
          values.push(ivar_value.inspect)
        end
      end

      format "#<%s:%#018x #{pattern.strip}>", self.class, object_id << 1, *values
    end
  end

  module BlobServiceMethod
    def service_encrypted?
      !!service&.try(:encrypted?)
    end

    def service
      actual_service = super
      if actual_service.try(:encrypted?)
        ServiceWrapperProvidingEncryptionKey.new(super, encryption_key)
      else
        actual_service
      end
    end

    def compose(keys)
      if service_encrypted?
        self.composed = true
        service.compose(keys, key, encryption_key: encryption_key, **service_metadata)
      else
        super
      end
    end

    # The encryption_key is binary and not serializabe to UTF-8 by to_json, thus we always want to
    # leave it out. This is also to better mimic how native ActiveStorage handles it.
    def serializable_hash(options = nil)
      options = if options
        options.merge(except: Array.wrap(options[:except]).concat([:encryption_key]).uniq)
      else
        {except: [:encryption_key]}
      end
      super
    end
  end
end
