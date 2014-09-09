require_relative './spec_helper'
require_relative '../lib/certificate_transparency'

describe "MerkleTreeLeaf" do
	let(:minicert) do
		"0w0m\xA0\x03\x02\x01\x02\x02\x01\x010\x03\x06\x01\x000\r1\v0\t\x06" +
		"\x03U\x04\x06\x13\x02AU0\x1E\x17\r140909060444Z\x17\r140909060448Z0" +
		"\r1\v0\t\x06\x03U\x04\x06\x13\x02AU0 0\r\x06\t*\x86H\x86\xF7\r\x01" +
		"\x01\x01\x05\x00\x03\x0F\x000\f\x02\x05\x00\xC2y\x11\x95\x02\x03\x01" +
		"\x00\x010\x03\x06\x01\x00\x03\x01\x00"
	end

	context "sending in a blob" do
		let(:mtl) do
			CertificateTransparency::MerkleTreeLeaf.from_blob(
			  "\0\0\0\0\x01G(W\xEC/\0\0" +
			  # X509 cert data length
			  "\0\0\x79" +
			  # X509 cert data
			  minicert +
			  # Extensions
			  "\0\0"
			)
		end

		it "gives us back a version" do
			expect(mtl.version).to eq(:v1)
		end

		it "has a timestamped_entry" do
			expect(mtl.timestamped_entry).to be_a(CertificateTransparency::TimestampedEntry)
		end

		context "TimestampedEntry" do
			let(:te) { mtl.timestamped_entry }

			it "has the right time" do
				expect(te.timestamp).to eq(Time.at(1405131156.527))
			end

			it "has the right entry_type" do
				expect(te.entry_type).to eq(:x509_entry)
			end

			it "has x509 entry data" do
				expect(te.x509_entry).to be_an(OpenSSL::X509::Certificate)
			end
		end
	end

	context "creating a new MTL TE" do
		let(:te) do
			CertificateTransparency::TimestampedEntry.new do |te|
				te.timestamp = Time.at(1405134233)
				te.x509_entry = minicert
			end
		end

		let(:mtl) do
			::CertificateTransparency::MerkleTreeLeaf.new do |mtl|
				mtl.timestamped_entry = te
			end
		end

		it "encodes the version correctly" do
			expect(mtl.to_blob[0]).to eq("\x00")
		end

		it "encodes the leaf_type correctly" do
			expect(mtl.to_blob[1]).to eq("\x00")
		end

		it "sets the ASN.1Cert length correctly" do
			expect(mtl.to_blob[12..14]).to eq("\0\0\x79")
		end

		it "includes the ASN.1Cert correctly" do
			expect(mtl.to_blob[15..135]).to eq(minicert)
		end

		it "has empty extensions" do
			expect(mtl.to_blob[136..137]).to eq("\0\0")
		end

		it "has nothing else at the end" do
			expect(mtl.to_blob.length).to eq(138)
		end
	end
end
