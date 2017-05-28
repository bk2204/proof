require 'openssl'

module ProofSig
  module Data
    # An entry representing a piece of data (e.g. a file) and its hash or
    # signature with a given algorithm (ans possibly key).
    class Entry
      attr_reader :algorithm, :value, :authority

      # @param algo [String, Algorithm] the algorithm in question
      # @param value [String] the hash or signature as a binary string
      def initialize(algo, value)
        @algorithm = algo.is_a?(Algorithm) || !algo ? algo : Algorithm.new(algo)
        @value = value
        @match = nil
        @authority = authority
      end

      def authority?(*args)
        args.include? authority
      end

      # Computes whether the signature or hash matches.
      def match?
        return @match unless @match.nil?

        compute == @value
      end
    end

    # An Entry representing a file.
    class FileEntry < Entry
      attr_reader :filename

      # @param algo [String, Algorithm] the algorithm in question
      # @param value [String] the hash or signature as a binary string
      # @param filename [String] the file name
      def initialize(algo, value, filename)
        super(algo, value)
        @filename = filename
      end

      protected

      def compute
        dig = algorithm.instance
        f = File.new(@filename, 'rb')
        while (buf = f.read(1024 * 1024))
          dig << buf
        end
        dig.digest
      end
    end

    # An Entry representing a file with a digital signature.
    class SignatureFileEntry < FileEntry
      def algorithm
        cached_compute
        @algorithm
      end

      def authority
        cached_compute
        @authority
      end

      def match?
        cached_compute
        @match
      end

      protected

      def cached_compute
        return if @computed
        compute
      end
    end

    # A stub representing a group of entries.
    class EntrySet < Array
    end

    # A hash algorithm.
    class Algorithm
      def initialize(name)
        data = lookup(name)
        raise InvalidAlgorithmError, name unless data
        @name = data[:name]
        @secure = data[:secure]
        @instance = data[:instance]
      end

      # Produces the name of the algorithm.
      def to_s
        @name
      end

      # Creates an instance of the algorithm.
      #
      # @return [#<<, #digest] an instance of a digest object
      def instance
        @instance.call
      end

      # Does the algorithm provide at least a 112-bit security level?
      def secure?
        @secure
      end

      protected

      MAPS = {
        /sha-?([01])/ => {
          name: ->(m) { "SHA-#{m[1]}" },
          secure: false,
          instance: ->(m) { OpenSSL::Digest.new m[1] == '1' ? 'SHA1' : 'SHA' },
        },
        /sha-?(\d{3})/ => {
          name: ->(m) { "SHA-#{m[1]}" },
          secure: true,
          instance: ->(m) { OpenSSL::Digest.new("SHA#{m[1]}") },
        },
        /sha-?(\d+\/\d+)/ => { # rubocop:disable RegexpLiteral
          name: ->(m) { "SHA-#{m[1]}" },
          secure: true,
        },
        /sha-?3-?(\d{3})/ => {
          name: ->(m) { "SHA3-#{m[1]}" },
          secure: true,
        },
        /shake-?(\d{3})/ => {
          name: ->(m) { "SHAKE-#{m[1]}" },
          secure: true,
        },
        /md-?(\d)/ => {
          name: ->(m) { "MD#{m[1]}" },
          secure: false,
          instance: ->(m) { OpenSSL::Digest.new("MD#{m[1]}") },
        },
      }.freeze

      def lookup(name)
        name = name.to_s.downcase
        MAPS.each do |re, val|
          m = /\A#{re}\z/.match name
          next unless m
          return transform(val, m)
        end
        nil
      end

      def transform(val, m)
        {
          name: val[:name].call(m),
          secure: val[:secure],
          instance: -> () { val[:instance].call(m) },
        }
      end
    end
  end
end
