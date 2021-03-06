require 'optparse'
require 'proof-sig/exception'
require 'proof-sig/parser'

module ProofSig
  module Program
    # Main program for proof-verify.
    class Verify
      def initialize(args, io = $stdout)
        @options, @args = parse_args(args)
        @io = io
      end

      def run
        entries = @args.flat_map do |file|
          options = @options.merge(signature_file: file)
          p, lines = parser(file)
          p.parse(lines, options)
        end
        verifier = ProofSig::Module::Verifier.new(entries, nil, @options)
        verifier.verify do |e, match, options = {}|
          @io.puts "#{e.filename}: #{match_text(match, options)}"
        end
        verifier.success? ? 0 : 1
      rescue StandardError => e
        raise if @options[:trace]
        $stderr.puts "E: #{e.class}: #{e}"
        2
      end

      protected

      def parser(file)
        lines = File.new(file, 'r').each_line.to_a
        reg = ProofSig::Module::ParserRegistry.instance
        chain = @options[:chain]
        klass = chain ? reg[chain] : reg.detect_class(lines[0])
        unless klass
          msg = chain ? "Unknown type #{chain}" : 'Could not detect file type'
          raise UnknownFileTypeError, msg
        end
        [klass.new, lines]
      end

      def match_text(match, options)
        if match
          'OK'
        elsif options[:missing]
          'MISSING'
        else
          'FAILED'
        end
      end

      def parse_args(args) # rubocop:disable Metrics/MethodLength
        options = {}
        OptionParser.new do |opts|
          opts.banner = 'Usage: proof-verify [options] FILES...'

          opts.on('--ignore-missing', 'Ignore missing files') do
            options[:ignore_missing] = true
          end

          opts.on('--ignore-malformed', 'Ignore malformed entries') do
            options[:ignore_malformed] = true
          end

          opts.on('--chain CHAIN', '-c CHAIN',
                  'Process data using these parsers') do |chain|
            options[:chain] = chain
          end

          opts.on('--file FILE', '-f FILE',
                  'Verify signature on this file') do |file|
            options[:file] = file
          end

          opts.on('--trace', 'Print a traceback on error') do
            options[:trace] = true
          end
        end.parse!(args)

        [options, args]
      end
    end
  end
end
