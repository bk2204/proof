require 'proof-sig/data'
require 'proof-sig/parser'
require 'open3'
require 'tempfile'

module ProofSig
  module Module
    # A parser for OpenPGP signature files.
    class OpenPGP < Parser
      # An Entry representing a signature over a data file.
      class OpenPGPFileEntry < ProofSig::Data::SignatureFileEntry
        protected

        def compute
          tf = Tempfile.new('proof-openpgp')
          tf.print value
          tf.flush
          stdout, _stderr, _status = Open3.capture3('gpg', '--status-fd=1',
                                                    '--verify', tf.path,
                                                    filename, binmode: true)
          data = process_output(stdout)
          @match = data[:match]
          @algorithm = data[:algorithm]
          @authority = data[:authority]
          nil
        end

        def process_output(stdout)
          data = {}
          stdout.each_line do |line|
            line.chomp!
            header, cmd, *items = line.split(' ')
            next unless header == '[GNUPG:]'
            case cmd
            when 'NEWSIG'
              # We anticipate that there might be multiple signatures, and we
              # always take the last one.
              data = {}
            when 'VALIDSIG'
              data[:algorithm] = algo(items[7].to_i)
              data[:authority] = items[9]
            when 'GOODSIG'
              data[:match] = true
            when 'BADSIG'
              data[:match] = false
            end
          end
          data
        end

        def algo(val)
          map = {
            1 => 'MD5',
            2 => 'SHA-1',
            3 => 'RIPEMD-160',
            8 => 'SHA-256',
            9 => 'SHA-384',
            10 => 'SHA-512',
            11 => 'SHA-224',
          }
          ProofSig::Data::Algorithm.new(map[val])
        end
      end

      PATTERN = /\A-----BEGIN PGP SIGNATURE-----\z/

      def self.detect(data)
        data.chomp =~ PATTERN
      end

      def parse(lines, options = {})
        s = ProofSig::Data::EntrySet.new
        sig = lines.to_a.join
        s << OpenPGPFileEntry.new(nil, sig, options[:file])
        s
      end
    end
  end
end

ProofSig::Module::ParserRegistry.instance.add('openpgp',
                                              ProofSig::Module::OpenPGP)
