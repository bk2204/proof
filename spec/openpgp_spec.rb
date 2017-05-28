require 'spec_helper'

require 'stringio'

describe ProofSig::Module::OpenPGP do
  let(:fixtures) { File.join(File.dirname(__FILE__), 'fixtures') }

  def signatures(s)
    File.join(fixtures, 'signatures', s)
  end

  def signature_over(s)
    p = ProofSig::Module::OpenPGP.new
    sig = File.open(signatures('openpgp-good'), 'r')
    tf = Tempfile.new('proof-rspec')
    tf.write s
    tf.flush
    p.parse(sig.each_line, file: tf.path)
  end

  def with_gnupg
    Dir.mktmpdir do |dir|
      env = ENV.to_h
      begin
        # We have to set this because the real code spawns binaries.
        ENV['GNUPGHOME'] = dir
        pubkey_path = File.join(fixtures, %w[keys openpgp-public])
        devnull = ['/dev/null', 'r+']
        pid = Process.spawn('gpg', '--batch', '--import', pubkey_path,
                            in: devnull, out: devnull, err: devnull)
        Process.wait pid
        yield dir
      ensure
        ENV.replace(env)
      end
    end
  end

  it 'should process valid GnuPG output for good signatures' do
    allow(Open3).to receive(:capture3).and_return(<<-EOM.sub(/^\s+/, ''))
    [GNUPG:] NEWSIG
    [GNUPG:] KEY_CONSIDERED 88ACE9B29196305BA9947552F1BA225C0223B187 0
    [GNUPG:] SIG_ID 9ZPuYmugSH9ATjHsOWTqL0bLMw0 2017-05-28 1496002763
    [GNUPG:] KEY_CONSIDERED 88ACE9B29196305BA9947552F1BA225C0223B187 0
    [GNUPG:] GOODSIG BF535D811F52F68B brian m. carlson <sandals@crustytoothpaste.net>
    [GNUPG:] VALIDSIG 5FC3A781776B26DF87F70C37BF535D811F52F68B 2017-05-28 1496002763 0 4 0 1 10 00 88ACE9B29196305BA9947552F1BA225C0223B187
    [GNUPG:] KEY_CONSIDERED 88ACE9B29196305BA9947552F1BA225C0223B187 0
    [GNUPG:] KEY_CONSIDERED 88ACE9B29196305BA9947552F1BA225C0223B187 0
    [GNUPG:] TRUST_ULTIMATE 0 tofu
    EOM
    sig = 'MOCKED'
    p = ProofSig::Module::OpenPGP.new
    output = p.parse(sig.each_line, file: '/nonexistent')
    expect(output.length).to eq 1
    expect(output[0].algorithm.to_s).to eq 'SHA-512'
    expect(output[0].match?).to be true
    expect(output[0].authority).to eq '88ACE9B29196305BA9947552F1BA225C0223B187'
  end

  it 'should process valid GnuPG output for bad signatures' do
    allow(Open3).to receive(:capture3).and_return(<<-EOM.sub(/^\s+/, ''))
    [GNUPG:] NEWSIG
    [GNUPG:] KEY_CONSIDERED 88ACE9B29196305BA9947552F1BA225C0223B187 0
    [GNUPG:] KEY_CONSIDERED 88ACE9B29196305BA9947552F1BA225C0223B187 0
    [GNUPG:] BADSIG BF535D811F52F68B brian m. carlson <sandals@crustytoothpaste.net>
    EOM
    sig = 'MOCKED'
    p = ProofSig::Module::OpenPGP.new
    output = p.parse(sig.each_line, file: '/nonexistent')
    expect(output.length).to eq 1
    expect(output[0].algorithm).to be nil
    expect(output[0].match?).to be false
    expect(output[0].authority).to be nil
  end

  it 'should verify good signatures over data' do
    with_gnupg do
      output = signature_over("foo\n")
      expect(output.length).to eq 1
      expect(output[0].algorithm.to_s).to eq 'SHA-256'
      expect(output[0].match?).to be true
      expect(output[0].authority).to eq \
        'A2A99A4490DBE0D9437733907E0008D9041506BD'
    end
  end

  it 'should reject bad signatures over data' do
    with_gnupg do
      output = signature_over('bar')
      expect(output.length).to eq 1
      expect(output[0].algorithm).to be nil
      expect(output[0].match?).to be false
      expect(output[0].authority).to be nil
    end
  end
end
