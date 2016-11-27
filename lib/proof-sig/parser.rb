require 'base64'
require 'singleton'

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

    # A registry of parser types.
    class ParserRegistry
      include Singleton
      include Enumerable

      # Adds the given class to the registry.
      #
      # @param name [String] name of the parser module
      # @param klass [Class] class of the parser module to add
      def add(name, klass)
        @entries[name] = klass
      end

      # Detects the parser module to for the given data.
      #
      # @param line [String] at least the first line of the data to parse
      # @param klass [Class] class of the parser module to add
      def detect_class(line)
        each do |_name, klass|
          return klass if klass.detect(line)
        end
        nil
      end

      # Iterates over the items.
      #
      # @yield [name, klass]
      # @yieldparam name [String] name of the parser module
      # @yieldparam klass [Class] class of the parser module
      def each
        @entries.sort.each { |k, v| yield [k, v] }
      end

      # Indicates whether the named parser exists.
      #
      # @param name [String] name of the parser module
      def include?(name)
        @entries.include?(name)
      end

      # Finds a parser module by name.
      #
      # @param name [String] name of the parser module
      def [](name)
        @entries[name]
      end

      protected

      def initialize
        @entries = {}
      end
    end
  end
end
