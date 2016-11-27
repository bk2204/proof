require 'proof-sig/parser'

module ProofSig
  module Module
    # Parses BSD-style hash files, such as those produced with FreeBSD's sha256.
    class BSDHash < Parser
      PATTERN = /\A(\w+) \(([^)]+)\) = ([a-f0-9]+)\z/

      def self.detect(data)
        data.chomp =~ PATTERN
      end

      def parse(lines, options = {})
        s = ProofSig::Data::EntrySet.new
        lines.each do |line|
          line.chomp!
          m = PATTERN.match line
          if m
            s << ProofSig::Data::FileEntry.new(m[1], from_hex(m[3]), m[2])
          else
            raise InvalidEntryError, line unless options[:ignore_malformed]
          end
        end
        s
      end
    end
  end
end

ProofSig::Module::ParserRegistry.instance.add('bsdhash',
                                              ProofSig::Module::BSDHash)
