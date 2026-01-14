require "./token"

module JWT
  class PublicKeys
    @keys : Hash(String, String)?
    @expires_at : Time?
    @mutex = Mutex.new

    def initialize
    end

    def get? : Hash(String, String)?
      @mutex.synchronize do
        return nil if @keys.nil?
        return nil if expired?
        @keys
      end
    end

    def update(keys : Hash(String, String), ttl : Time::Span)
      @mutex.synchronize do
        @keys = keys
        @expires_at = Time.utc + ttl
      end
    end

    def clear
      @mutex.synchronize do
        @keys = nil
        @expires_at = nil
      end
    end

    def expires_at : Time?
      @expires_at
    end

    def decode(token : String) : Token
      keys = get?
      raise ExpiredKeysError.new("Public keys unavailable or expired") unless keys

      kid = RS256Parser.decode_header(token)["kid"]?.try(&.as_s) rescue nil
      if kid && keys[kid]?
        return RS256Parser.decode(token, keys[kid], verify: true)
      end

      keys.each_value do |key|
        return RS256Parser.decode(token, key, verify: true)
      rescue VerificationError
      end
      raise VerificationError.new("Could not verify JWT with any key")
    end

    private def expired? : Bool
      if expires_at = @expires_at
        Time.utc >= expires_at
      else
        true
      end
    end
  end
end
