require_relative './spec_helper'
require_relative '../lib/certificate_transparency'

require 'digest/sha2'

describe "TimestampedEntry" do
	let(:minicert) do
		"0w0m\xA0\x03\x02\x01\x02\x02\x01\x010\x03\x06\x01\x000\r1\v0\t\x06" +
		"\x03U\x04\x06\x13\x02AU0\x1E\x17\r140909060444Z\x17\r140909060448Z0" +
		"\r1\v0\t\x06\x03U\x04\x06\x13\x02AU0 0\r\x06\t*\x86H\x86\xF7\r\x01" +
		"\x01\x01\x05\x00\x03\x0F\x000\f\x02\x05\x00\xC2y\x11\x95\x02\x03\x01" +
		"\x00\x010\x03\x06\x01\x00\x03\x01\x00"
	end

	# Raw uint64 timestamp for both of these is 1405131156527
	context "sending in an X509-shaped blob" do
		let(:te) do
			# This blob is hand-crafted from the finest bits to have a useful
			# set of values for testing (but not much value in the real world)
			CertificateTransparency::TimestampedEntry.from_blob(
			  "\0\0\x01G(W\xEC/\0\0\0\0\x79#{minicert}\0\0"
			)
		end

		it "gives us back a Time" do
			expect(te.timestamp).to be_a(Time)
		end

		it "gives us back the *right* Time" do
			expect(te.timestamp).to eq(Time.at(1405131156.527))
		end

		it "gives us back the right entry_type" do
			expect(te.entry_type).to eq(:x509_entry)
		end

		it "doesn't have a precert_entry" do
			expect(te.precert_entry).to be(nil)
		end

		it "has the right x509_entry" do
			expect(te.x509_entry).to be_an(OpenSSL::X509::Certificate)
		end

		it "sets signed_entry to the x509_entry" do
			expect(te.signed_entry).to eq(te.x509_entry)
		end
	end

	context "sending in a PreCert-shaped blob" do
		let(:te) do
			# Another hand-crafted blob, this time with extra pickles
			CertificateTransparency::TimestampedEntry.from_blob(
			  "\x00\x00\x01G(W\xEC/\x00\x01\xE8G\x12#\x87\t9\x8Fm4\x9D\xC2" +
			  "%\v\x0E\xFC\xA4\xB7-\x8C+\xFB{t3\x9D0\xBA\x94\x05k\x14\x00" +
			  "\x00\"What is a TBS Certificate, anyway?\x00\x00"
			)
		end

		it "gives us back a Time" do
			expect(te.timestamp).to be_a(Time)
		end

		it "gives us back the *right* Time" do
			expect(te.timestamp).to eq(Time.at(1405131156.527))
		end

		it "gives us back the right entry_type" do
			expect(te.entry_type).to eq(:precert_entry)
		end

		it "doesn't have an x509_entry" do
			expect(te.x509_entry).to be(nil)
		end

		it "has a precert_entry" do
			expect(te.precert_entry).to be_a(CertificateTransparency::PreCert)
		end

		context "PreCert" do
			let(:precert) { te.precert_entry }

			it "has the right issuer_key_hash" do
				expect(precert.issuer_key_hash).to eq(Digest::SHA256.digest("ohai"))
			end

			it "has the right tbs_certificate" do
				expect(precert.tbs_certificate).to eq("What is a TBS Certificate, anyway?")
			end
		end

		it "sets signed_entry to the precert_entry" do
			expect(te.signed_entry).to eq(te.precert_entry)
		end
	end

	context "creating a TE with a Time" do
		let(:te) do
			CertificateTransparency::TimestampedEntry.new do |te|
				te.timestamp  = Time.at(1405134233)
				te.x509_entry = minicert
			end
		end

		it "encodes the time correctly" do
			expect(te.to_blob[0..7]).to eq("\x00\x00\x01G(\x86\xDD\xA8")
		end
	end

	context "creating a new X509-shaped TE" do
		let(:te) do
			CertificateTransparency::TimestampedEntry.new do |te|
				te.timestamp  = Time.at(1405134233)
				te.x509_entry = minicert
			end
		end

		it "encodes the timestamp correctly" do
			expect(te.to_blob[0..7]).to eq("\x00\x00\x01G(\x86\xDD\xA8")
		end

		it "sets the correct LogEntryType" do
			expect(te.to_blob[8..9]).to eq("\0\0")
		end

		it "sets the ASN.1Cert length correctly" do
			expect(te.to_blob[10..12]).to eq("\0\0\x79")
		end

		it "includes the ASN.1Cert correctly" do
			expect(te.to_blob[13..133]).to eq(minicert)
		end

		it "has empty extensions" do
			expect(te.to_blob[134..135]).to eq("\0\0")
		end

		it "has nothing else at the end" do
			expect(te.to_blob.length).to eq(136)
		end
	end
end
