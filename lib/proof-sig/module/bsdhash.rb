require 'proof-sig/parser'

module ProofSig
  module Module
    # Parses BSD-style hash files, such as those produced with FreeBSD's sha256.
    class BSDHash < Parser
      def parse(lines, options = {})
        s = ProofSig::Data::EntrySet.new
        re = /\A(\w+) \(([^)]+)\) = ([a-f0-9]+)\z/
        lines.each_line do |line|
          line.chomp!
          m = re.match line
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
