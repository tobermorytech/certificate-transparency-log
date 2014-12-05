# An RFC6962 TimestampedEntry structure
#
# Use ::from_blob(blob) if you have an encoded TE you wish to decode,
# or create a new instance, set the various parameters, and use `#to_blob`
# to give you an encoded structure you can put over the wire.  The various
# elements of the TE struct are available via accessors.
#
class CertificateTransparency::TimestampedEntry
	# An instance of Time representing the timestamp of this entry
	attr_reader :timestamp

	# The type of entry we've got here.  Is a symbol, either
	# :x509_entry or :precert_entry.
	attr_reader :entry_type

	# An OpenSSL::X509::Certificate instance, if `entry_type == :x509_entry`,
	# or nil otherwise.
	attr_reader :x509_entry

	# An instance of ::CertificateTransparency::PreCert if `entry_type ==
	# :precert_entry`, or nil otherwise.
	attr_reader :precert_entry

	def self.from_blob(blob)
		ts_hi, ts_lo, entry_type, rest = blob.unpack("NNna*")
		ts = ts_hi * 2**32 + ts_lo

		self.new do |te|
			te.timestamp = Time.at(ts / 1000.0)

			case CertificateTransparency::LogEntryType.invert[entry_type]
			when :x509_entry
				cert_data, rest = TLS::Opaque.from_blob(rest, 2**24-1)
				te.x509_entry = OpenSSL::X509::Certificate.new(cert_data.value)
			when :precert_entry
				# Holy fuck, can I have ASN1 back, please?  I can't just pass
				# the PreCert part of the blob into CT::PreCert.new, because I
				# can't parse the PreCert part out of the blob without digging
				# *into* the PreCert part, because the only information on how
				# long TBSCertificate is is contained *IN THE PRECERT!*
				#
				# I'm surprised there aren't a lot more bugs in TLS
				# implementations, if this is how they lay out their data
				# structures.
				ikh, tbsc_len_hi, tbsc_len_lo, rest = rest.unpack("a32nCa*")
				tbsc_len = tbsc_len_hi * 256 + tbsc_len_lo
				tbsc, rest = rest.unpack("a#{tbsc_len}a*")
				te.precert_entry = ::CertificateTransparency::PreCert.new do |ctpc|
					ctpc.issuer_key_hash = ikh
					ctpc.tbs_certificate = tbsc
				end
			else
				raise ArgumentError,
				      "Unknown LogEntryType: #{entry_type} (corrupt TimestampedEntry?)"
			end

			exts, rest = TLS::Opaque.from_blob(rest, 2**16-1)
			unless exts.value == ""
				raise ArgumentError,
				      "Non-empty extensions found (#{exts.value.inspect})"
			end

			unless rest == ""
				raise ArgumentError,
				      "Corrupted blob (garbage data after extensions)"
			end
		end
	end

	# Create a new TimestampedEntry
	#
	# You can't pass any options into this constructor, but if you
	# pass in a block you'll get the new instance yielded to it, so you can
	# one-liner it anyway.
	def initialize
		yield self if block_given?
	end

	# Gives you whichever of `#x509_entry` or `#precert_entry` is
	# not nil, or `nil` if both of them are `nil`.
	def signed_entry
		@x509_entry or @precert_entry
	end

	# Set the timestamp for this entry
	#
	# Must be a Time object, or something that can be bludgeoned
	# into a Time object.
	def timestamp=(ts)
		unless ts.is_a? Time or ts.respond_to? :to_time
			raise ArgumentError,
			      "Must pass me a Time or something that responds to :to_time"
		end

		@timestamp = ts.is_a?(Time) ? ts : ts.to_time
	end

	# Set the entry to be an x509_entry with the given certificate.
	def x509_entry=(xe)
		@x509_entry = OpenSSL::X509::Certificate.new(xe.to_s)
		@entry_type = :x509_entry
		@precert_entry = nil
	end

	# Set the entry to be a precert_entry with the given precert data.  You
	# must pass in a CertificateTransparency::PreCert instance.
	def precert_entry=(pe)
		unless pe.is_a? ::CertificateTransparency::PreCert
			raise ArgumentError,
			      "I only accept PreCert instances (you gave me a #{pe.class})"
		end

		@precert_entry = pe
		@entry_type = :precert_entry
		@x509_entry = nil
	end

	def to_blob
		signed_entry = if @x509_entry
			TLS::Opaque.new(@x509_entry.to_der, 2**24-1).to_blob
		elsif @precert_entry
			@precert_entry.to_blob
		else
			raise RuntimeError,
			      "You must call #precert_entry= or #x509_entry= before calling #to_blob"
		end

		ts_hi = (@timestamp.to_f*1000).round / 2**32
		ts_lo = (@timestamp.to_f*1000).round % 2**32
		[ts_hi, ts_lo,
		 CertificateTransparency::LogEntryType[entry_type],
		 signed_entry, 0
		].pack("NNna*n")
	end
end
