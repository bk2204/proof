require 'spec_helper'

describe ProofSig::Module::GNUSum do
  it 'should parse SHA-256 lines' do
    input = <<EOM
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  /dev/null
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  /dev/full
EOM
    p = ProofSig::Module::GNUSum.new
    output = p.parse(input.each_line).map do |x|
      [x.algorithm.to_s, x.value.unpack('H*')[0].downcase, x.filename]
    end
    expect(output).to eq [
      %w(SHA-256
         e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
         /dev/null),
      %w(SHA-256
         ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
         /dev/full),
    ]
  end
end
