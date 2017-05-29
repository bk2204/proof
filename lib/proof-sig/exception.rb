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

  # Raised when required data is missing.
  class MissingDataError < ProofSig::Exception
  end

  # Raised when an unknown file type occurs.
  class UnknownFileTypeError < ProofSig::Exception
  end
end
