require 'tls'
require 'time_extension'

# Implement the CertificateTimestamp structure as defined by RFC6962, s3.2.
#
class CertificateTransparency::CertificateTimestamp
	def initialize
		yield self if block_given?
	end

	def x509_entry=(v)
		@entry_type = :x509_entry
		@signed_entry = v.to_der
	end

	def precert_entry=(v)
		@entry_type = :precert_entry
		@signed_entry = v.to_blob
	end

	def timestamp=(ts)
		@timestamp = ts.is_a?(Time) ? ts : ts.to_time
	end

	def to_blob
		[::CertificateTransparency::Version[:v1],
		 ::CertificateTransparency::SignatureType[:certificate_timestamp],
		 @timestamp.to_ms,
		 ::CertificateTransparency::LogEntryType[@entry_type],
		 TLS::Opaque.new(@signed_entry, 2**24-1).to_blob,
		 TLS::Opaque.new("", 2**16-1).to_blob   # CtExtensions, guaranteed to be empty
		].pack("CCQ>na*a*")
	end
end
