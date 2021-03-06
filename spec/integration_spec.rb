require 'spec_helper'

describe ProofSig::Program::Verify do
  before(:each) do
    @dir = Dir.mktmpdir
    File.new("#{@dir}/a", 'w').close
    f = File.new("#{@dir}/b", 'w')
    f.print('abc')
    f.close
  end

  after(:each) do
    FileUtils.remove_entry @dir
  end

  it 'should process basic GNU sum files' do
    h = File.new("#{@dir}/hashes", 'w')
    h.print(<<-EOM.gsub(/^\s+/, ''))
    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  #{@dir}/a
    ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  #{@dir}/b
    EOM
    h.close

    expected = <<-EOM.gsub(/^\s+/, '')
    #{@dir}/a: OK
    #{@dir}/b: OK
    EOM

    io = StringIO.new('', 'w')
    prog = ProofSig::Program::Verify.new(["#{@dir}/hashes"], io)
    expect(prog.run).to eq 0
    expect(io.string).to eq expected
  end

  it 'should process basic BSD hash files' do
    h = File.new("#{@dir}/hashes", 'w')
    h.print(<<-EOM.gsub(/^\s+/, ''))
    SHA256 (#{@dir}/a) = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    SHA256 (#{@dir}/b) = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    EOM
    h.close

    expected = <<-EOM.gsub(/^\s+/, '')
    #{@dir}/a: OK
    #{@dir}/b: OK
    EOM

    io = StringIO.new('', 'w')
    prog = ProofSig::Program::Verify.new(["#{@dir}/hashes"], io)
    expect(prog.run).to eq 0
    expect(io.string).to eq expected
  end

  it 'should raise an exception when malformed data' do
    h = File.new("#{@dir}/hashes", 'w')
    h.print(<<-EOM.gsub(/^\s+/, ''))
    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 #{@dir}/a
    EOM
    h.close

    io = StringIO.new('', 'w')
    prog = ProofSig::Program::Verify.new(['-c', 'gnusum', "#{@dir}/hashes"], io)
    errors = []
    allow($stderr).to receive(:puts) { |msg| errors << msg }
    expect(prog.run).to eq 2
    expect(errors[0]).to match(/\AE: ProofSig::InvalidEntryError:/)
  end

  it 'should ignore malformed entries when requested' do
    h = File.new("#{@dir}/hashes", 'w')
    h.print(<<-EOM.gsub(/^\s+/, ''))
    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 #{@dir}/a
    ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  #{@dir}/b
    EOM
    h.close

    expected = <<-EOM.gsub(/^\s+/, '')
    #{@dir}/b: OK
    EOM

    io = StringIO.new('', 'w')
    prog = ProofSig::Program::Verify.new(['--ignore-malformed',
                                          '-c', 'gnusum',
                                          "#{@dir}/hashes"], io)
    expect(prog.run).to eq 0
    expect(io.string).to eq expected
  end

  it 'should ignore missing entries when requested' do
    h = File.new("#{@dir}/hashes", 'w')
    h.print(<<-EOM.gsub(/^\s+/, ''))
    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  #{@dir}/a
    ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  #{@dir}/c
    EOM
    h.close

    expected = <<-EOM.gsub(/^\s+/, '')
    #{@dir}/a: OK
    #{@dir}/c: MISSING
    EOM

    io = StringIO.new('', 'w')
    prog = ProofSig::Program::Verify.new(['--ignore-missing',
                                          '-c', 'gnusum',
                                          "#{@dir}/hashes"], io)
    expect(prog.run).to eq 0
    expect(io.string).to eq expected
  end

  it 'should mark mismatches as failed' do
    h = File.new("#{@dir}/hashes", 'w')
    h.print(<<-EOM.gsub(/^\s+/, ''))
    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  #{@dir}/a
    0000000000000000000000000000000000000000000000000000000000000000  #{@dir}/b
    EOM
    h.close

    expected = <<-EOM.gsub(/^\s+/, '')
    #{@dir}/a: OK
    #{@dir}/b: FAILED
    EOM

    io = StringIO.new('', 'w')
    prog = ProofSig::Program::Verify.new(['-c', 'gnusum',
                                          "#{@dir}/hashes"], io)
    expect(prog.run).to eq 1
    expect(io.string).to eq expected
  end
end
