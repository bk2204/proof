require 'spec_helper'

describe ProofSig::Module::BSDHash do
  it 'should parse SHA-256 lines' do
    input = <<EOM
SHA256 (/dev/null) = f373dbdb9ce80c4f1b4a50d565356a1172d42ad00cf2c4cbe3131d0b566db5b4
SHA256 (/dev/full) = 49dcf35eabae9f63660f29f302f3854e05d4cdc046e4cfcef91abf23631c64d6
EOM
    p = ProofSig::Module::BSDHash.new
    output = p.parse(input.each_line).map do |x|
      [x.algorithm.to_s, x.value.unpack('H*')[0].downcase, x.filename]
    end
    expect(output).to eq [
      %w(SHA-256
         f373dbdb9ce80c4f1b4a50d565356a1172d42ad00cf2c4cbe3131d0b566db5b4
         /dev/null),
      %w(SHA-256
         49dcf35eabae9f63660f29f302f3854e05d4cdc046e4cfcef91abf23631c64d6
         /dev/full),
    ]
  end
end
