require 'spec_helper'

describe ProofSig::Module::ParserRegistry do
  it 'should have at least some basic entries' do
    reg = ProofSig::Module::ParserRegistry.instance
    expect(reg.include?('bsdhash')).to be true
    expect(reg.include?('gnusum')).to be true
    expect(reg['bsdhash']).to be ProofSig::Module::BSDHash
    expect(reg['gnusum']).to be ProofSig::Module::GNUSum
  end

  it 'should iterate with keys and values' do
    reg = ProofSig::Module::ParserRegistry.instance
    reg.each do |name, klass|
      expect(name).to be_a String
      expect(klass).to be_a Class
    end
  end
end
