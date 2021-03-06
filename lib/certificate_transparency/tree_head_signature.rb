require 'certificate_transparency'
require 'time_extension'

# Implement the TreeHeadSignature structure as defined by RFC6962, s3.5.
#
# Instances of this class are populated by specifying either a string "blob"
# of data (which is assumed to be an existing TreeHeadSignature, and is
# parsed for values), or else passing in a hash of `:key => value` pairs
# to populate the various elements of the structure.  Any elements not
# specified will be left undefined; this may prevent the structure from
# being serialised.
#
#
# # Examples
#
# Take a binary string (which is presumed to be an encoded TreeHeadSignature)
#
#     ths = CertificateTransparency::TreeHeadSignature.new("<opaque binary string>")
#
#     puts "Version is #{ths.version}"
#     puts "Tree size is #{tbs.tree_size}"
#
class CertificateTransparency::TreeHeadSignature
	def self.from_blob(blob)
		res = blob.unpack("CCQ>Q>a32")

		self.new(
		  :version          => res[0],
		  :signature_type   => res[1],
		  :timestamp        => Time.from_ms(res[2]),
		  :tree_size        => res[3],
		  :sha256_root_hash => res[4]
		)
	end

	attr_reader :version, :signature_type, :timestamp, :tree_size,
	            :sha256_root_hash

	# Create a new TreeHeadSignature instance
	#
	# You can pass either an encoded TreeHeadSignature struct, as a string,
	# or else a hash of `:key => value` pairs which represent elements of
	# the structure you want to populate.
	#
	# Raises:
	#
	# * `ArgumentError` -- if `blob_or_opts` is not a String or Hash, or if
	#   the provided string cannot be decoded, or if an unknown struct
	#   element is specified in the hash.
	#
	def initialize(opts={})
		[:version, :signature_type, :timestamp, :tree_size, :sha256_root_hash].each do |k|
			if opts.has_key?(k)
				__send__("#{k}=".to_sym, opts.delete(k))
			end
		end

		@signature_type = CertificateTransparency::SignatureType[:tree_hash]

		unless opts.empty?
			raise ArgumentError,
			      "Unknown struct elements passed: #{opts.keys.inspect}"
		end
	end

	# Encode the elements of this item into a binary blob.
	#
	# Returns a binary string with the encoded contents of this object, as
	# defined by RFC6962.  Will raise a `RuntimeError` if any parameters are
	# missing (haven't been defined).
	def to_blob
		missing = []
		[:version, :signature_type, :timestamp, :tree_size, :sha256_root_hash].each do |e|
			if instance_variable_get("@#{e}".to_sym).nil?
				missing << e
			end
		end

		unless missing.empty?
			raise RuntimeError,
			      "Cannot encode #{to_s}; missing element(s) #{missing.inspect}"
		end

		[@version,
		 @signature_type,
		 @timestamp.to_ms,
		 @tree_size,
		 @sha256_root_hash
		].pack("CCQ>Q>a32")
	end

	# Set the version on this TreeHeadSignature
	def version=(v)
		unless ::CertificateTransparency::Version.values.include?(v)
			raise ArgumentError,
			      "Invalid version #{v}"
		end

		@version = v
	end

	# Set the timestamp on this TreeHeadSignature
	def timestamp=(t)
		unless t.is_a? Time or t.respond_to?(:to_time)
			raise ArgumentError,
			      "Can only set timestamp to a Time or time-like object"
		end

		@timestamp = t.is_a?(Time) ? t : t.to_time
	end

	# Set the tree size on this TreeHeadSignature
	def tree_size=(s)
		unless s.is_a? Integer
			raise ArgumentError,
			      "tree_size must be an integer"
		end

		unless s >= 0
			raise ArgumentError,
			      "tree_size cannot be negative"
		end

		@tree_size = s
	end

	# Set the sha256_root_hash on this TreeHeadSignature
	def sha256_root_hash=(h)
		unless h.is_a? String
			raise ArgumentError,
			      "sha256_root_hash must be a string"
		end

		unless h.length == 32
			raise ArgumentError,
			      "sha256_root_hash must be exactly 32 bytes long"
		end

		@sha256_root_hash = h
	end
end
