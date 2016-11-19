module ProofSig
  # Base class for all Proof exceptions.
  class Exception < StandardError
  end

  # Raised when an entry is invalid.
  class InvalidEntryError < ProofSig::Exception
  end

  # Raised when the algorithm is unknown.
  class InvalidAlgorithmError < ProofSig::Exception
  end
end
