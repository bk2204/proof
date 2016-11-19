require 'base64'

module ProofSig
  module Module
    # Base class for file parsing.
    class Parser
      protected

      def from_hex(s)
        [s].pack('H*')
      end

      def from_base64(s)
        Base64.decode64(s)
      end
    end

    # Verifies whether a set of entries match files.
    class Verifier
      # @param entries [Enumerable<ProofSig::Data::Entry>] sequence of entries
      #   to verify
      # @param key Key to use to perform verification
      # @param options [Hash] options controlling verification
      def initialize(entries, key = nil, options = {})
        @entries = entries
        @key = key
        @options = options
      end

      # Verifies the entries.
      #
      # @yield [e, match, options]
      # @yieldparam e [ProofSig::Data::Entry] the entry being verified
      # @yieldparam match [true, false, nil] whether the entry matched, or
      #   nil if the entry was ignored
      # @yieldparam options [Hash} other metadata about the match
      def verify
        @entries.each do |ent|
          begin
            match = ent.match?
            yield ent, match
          rescue Errno::ENOENT
            raise unless @options[:ignore_missing]
            yield ent, nil, missing: true
          end
        end
      end
    end
  end
end
