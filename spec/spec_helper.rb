if ENV['COVERAGE']
  require 'simplecov'

  SimpleCov.start do
    add_filter '/spec/'
    add_filter '/.bundle/'
  end
end

require 'stringio'
require 'tmpdir'
require_relative '../lib/proof-sig'
require_relative '../lib/proof-sig/main'
