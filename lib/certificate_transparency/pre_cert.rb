# Yet another structure... this time, for the CT PreCert.
#
class CertificateTransparency::PreCert
	attr_reader :issuer_key_hash, :tbs_certificate

	def self.from_blob(blob)
		@issuer_key_hash, rest = blob.unpack("a32a*")

		tbscert, rest = TLS::Opaque.from_blob(rest, 2**24-1)

		@tbs_certificate = tbscert.value

		unless rest == ""
			raise ArgumentError,
			      "Garbage at end of blob"
		end
	end

	def initialize
		yield self if block_given?
	end

	def issuer_key_hash=(v)
		unless v.is_a? String and v.length == 32
			raise ArgumentError,
			      "issuer_key_hash must be a 32 character string"
		end

		@issuer_key_hash = v
	end

	def tbs_certificate=(v)
		unless v.is_a? String
			raise ArgumentError,
			      "tbs_certificate must be a String"
		end
		@tbs_certificate = v
	end

	def to_blob
		[@issuer_key_hash,
		 TLS::Opaque.new(@tbs_certificate, 2**24-1).to_blob
		].pack("a32a*")
	end
end
