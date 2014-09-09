# An RFC6962 MerkleTreeLeaf structure
#
# Use ::from_blob(blob) if you have an encoded MTL you wish to decode, or
# else create a new instance, pass in a `TimestampedEntry` object via
# `#timestamped_entry=`, and then call `#to_blob` to get the encoded MTL.
#
class CertificateTransparency::MerkleTreeLeaf
	attr_reader :timestamped_entry

	# Return a new MerkleTreeLeaf instance, from a binary blob of data.
	# Raises an ArgumentError if the blob is invalid in some way.
	def self.from_blob(blob)
		self.new do |mtl|
			mtl.version, leaf_type, te = blob.unpack("CCa*")
			unless leaf_type == ::CertificateTransparency::MerkleLeafType[:timestamped_entry]
				raise ArgumentError,
				      "Unknown leaf type in blob"
			end

			mtl.timestamped_entry =
			     ::CertificateTransparency::TimestampedEntry.from_blob(te)
		end
	end

	# Instantiate a new MerkleTreeLeaf.
	#
	# You can't set parameters as arguments, but if you pass a block,
	# the newly-created MTL instance will be yielded to it, so you can
	# do:
	#
	#     MerkleTreeLeaf.new { |mtl| mtl.timestamped_entry = te }.to_blob
	#
	# For all your one-liner goodness.
	#
	def initialize
		@version   = ::CertificateTransparency::Version[:v1]
		@leaf_type = ::CertificateTransparency::MerkleLeafType[:timestamped_entry]

		yield self if block_given?
	end

	# Set the version of the MerkleTreeLeaf structure to create.  At present,
	# only `:v1` is supported, so there isn't much point in ever calling this
	# method.
	def version=(v)
		unless v == :v1 or v == ::CertificateTransparency::Version[:v1]
			raise ArgumentError,
			      "Invalid version.  We only know about :v1"
		end
	end

	# Return a symbol indicating the version of the MerkleTreeLeaf structure
	# represented by this object.  At present, only `:v1` is supported.
	def version
		:v1
	end

	# Set the TimestampedEntry element for this MerkleTreeLeaf.  It must be
	# an instance of CertificateTransparency::TimestampedEntry, or an
	# ArgumentError will be raised.
	def timestamped_entry=(te)
		unless te.is_a? ::CertificateTransparency::TimestampedEntry
			raise ArgumentError,
			      "Wasn't passed a TimestampedEntry (got a #{te.class})"
		end

		@timestamped_entry = te
	end

	# Generate a binary blob representing this MerkleTreeLeaf structure.
	def to_blob
		if @timestamped_entry.nil?
			raise RuntimeError,
			      "timestamped_entry has not been set"
		end

		[@version, @leaf_type, @timestamped_entry.to_blob].pack("CCa*")
	end
end
