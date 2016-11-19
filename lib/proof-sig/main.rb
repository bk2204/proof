require 'optparse'
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
        parser = ProofSig::Module::GNUSum.new
        entries = @args.flat_map do |file|
          parser.parse(File.new(file, 'r'), @options)
        end
        verifier = ProofSig::Module::Verifier.new(entries, nil, @options)
        verifier.verify do |e, match, options = {}|
          @io.puts "#{e.filename}: #{match_text(match, options)}"
        end
      end

      protected

      def match_text(match, options)
        if match
          'OK'
        elsif options[:missing]
          'MISSING'
        else
          'FAILED'
        end
      end

      def parse_args(args)
        options = {}
        OptionParser.new do |opts|
          opts.banner = 'Usage: proof-verify [options] FILES...'

          opts.on('--ignore-missing', 'Ignore missing files') do
            options[:ignore_missing] = true
          end

          opts.on('--ignore-malformed', 'Ignore malformed entries') do
            options[:ignore_malformed] = true
          end
        end.parse!(args)

        [options, args]
      end
    end
  end
end
