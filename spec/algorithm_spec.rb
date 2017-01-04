require 'spec_helper'

describe ProofSig::Data::Algorithm do
  it 'should recognize basic SHA-2 algorithms' do
    %w(
      SHA-224 SHA-256 SHA-384 SHA-512
      sha224 sha256 sha384 sha512
    ).each do |name|
      a = ProofSig::Data::Algorithm.new name
      m = /(\d{3})$/.match name
      expect(a.to_s).to eq "SHA-#{m[1]}"
      expect(a.secure?).to be true
      expect(a.instance).to be_a OpenSSL::Digest
    end
  end

  it 'should recognize extended SHA-2 algorithms' do
    %w(SHA-512/256 SHA-512/224).each do |name|
      a = ProofSig::Data::Algorithm.new name
      expect(a.to_s).to eq name
      expect(a.secure?).to be true
    end
  end

  it 'should recognize extended SHA-3 algorithms' do
    %w(SHA3-512 SHA3-384 SHA3-256 SHA3-224 SHAKE-128 SHAKE-256).each do |name|
      a = ProofSig::Data::Algorithm.new name
      expect(a.to_s).to eq name
      expect(a.secure?).to be true
    end
  end

  it 'should recognize common but insecure algorithms' do
    %w(MD2 MD4 MD5 SHA-0 SHA-1).each do |name|
      a = ProofSig::Data::Algorithm.new name
      expect(a.to_s).to eq name
      expect(a.secure?).to be false
    end
  end
end
