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
          tf = write_tempfile(value)
          args = %w[gpg --status-fd=1 --verify] + [tf.path]
          args << verification_filename if verification_filename
          stdout, _stderr, _status = Open3.capture3(*args, binmode: true)
          process_parsed_data(process_output(stdout))
          nil
        end

        def write_tempfile(value)
          tf = Tempfile.new('proof-openpgp')
          tf.print value
          tf.flush
          tf
        end

        def process_parsed_data(data)
          @match = data[:match]
          @algorithm = data[:algorithm]
          @authority = data[:authority]
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

      # An Entry representing a detached signature over a data file.
      class DetachedOpenPGPFileEntry < OpenPGPFileEntry
        protected

        def verification_filename
          filename
        end
      end

      # An Entry representing an inline signature over a data file.
      class InlineOpenPGPFileEntry < OpenPGPFileEntry
        protected

        def verification_filename
          nil
        end
      end

      SIG_PATTERN = '-----BEGIN PGP SIGNATURE-----'.freeze
      MSG_PATTERN = '-----BEGIN PGP SIGNED MESSAGE-----'.freeze

      def self.detect(data)
        data = data.chomp
        return :detached if data == SIG_PATTERN
        return :inline if data == MSG_PATTERN
        nil
      end

      def parse(lines, options = {})
        first = lines.first
        type = self.class.detect(first)
        sig = first + lines.to_a.join
        s = ProofSig::Data::EntrySet.new
        s << if type == :detached
               unless options[:file]
                 raise ProofSig::MissingDataError,
                       'file is required for OpenPGP detached signatures'
               end
               DetachedOpenPGPFileEntry.new(nil, sig, options[:file])
             else
               InlineOpenPGPFileEntry.new(nil, sig, options[:signature_file])
             end
        s
      end
    end
  end
end

ProofSig::Module::ParserRegistry.instance.add('openpgp',
                                              ProofSig::Module::OpenPGP)
