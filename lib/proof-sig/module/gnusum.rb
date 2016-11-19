require 'proof-sig/parser'

module ProofSig
  module Module
    # A parser for the GNU coreutils sha*sum style files.
    #
    # Lines in this format consist of a hex-encoded hash, a space, a file type
    # indicator character (space for text mode, asterisk for binary), and the
    # file name.
    class GNUSum < Parser
      ALGORITHM_MAP = {
        32  => :md5,
        40  => :sha1,
        64  => :sha256,
        96  => :sha384,
        128 => :sha512,
      }.freeze

      def parse(lines, options = {})
        s = ProofSig::Data::EntrySet.new
        re = /\A([a-f0-9]+) [ *](.+)\z/
        lines.each_line do |line|
          line.chomp!
          m = re.match line
          unless m
            raise InvalidEntryError, line unless options[:ignore_malformed]
            next
          end
          s << process_match(m, options)
        end
        s
      end

      protected

      def process_match(m, options)
        hash = m[1]
        algo = ALGORITHM_MAP[hash.length]
        raise InvalidEntryError, line unless algo || options[:ignore_malformed]
        ProofSig::Data::FileEntry.new(algo, from_hex(hash), m[2])
      end
    end
  end
end
