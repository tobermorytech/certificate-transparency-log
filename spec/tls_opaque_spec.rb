require_relative './spec_helper'
require_relative '../lib/tls'

describe "TLS::Opaque" do
	context "::from_blob" do
		it "freaks out if len > max_len" do
			expect do
				TLS::Opaque.from_blob("\x0CHello World!", 5)
			end.to raise_error(ArgumentError)
		end

		it "freaks out if len > blob.length" do
			expect do
				TLS::Opaque.from_blob("\x10Hello World!", 255)
			end.to raise_error(ArgumentError)
		end

		context "when given the exact length blob" do
			let(:rv) { TLS::Opaque.from_blob("\x04ohai", 255) }

			it "returns a good-looking blob" do
				expect(rv[0].value).to eq("ohai")
			end

			it "returns an empty string" do
				expect(rv[1]).to eq("")
			end
		end

		context "when given a blob with extra bits" do
			let(:rv) { TLS::Opaque.from_blob("\x04ohai!", 255) }

			it "returns a good-looking blob" do
				expect(rv[0].value).to eq("ohai")
			end

			it "returns some leftovers" do
				expect(rv[1]).to eq("!")
			end
		end
	end

	it "fails if the max length is something craycray" do
		expect { TLS::Opaque.new("x", "craycray") }.
		  to raise_error(ArgumentError, /Integer/)
	end

	it "fails when given a value that is too long" do
		expect { TLS::Opaque.new("abcdef", 5) }.
		  to raise_error(ArgumentError, /5/)
	end

	# If you're encoding a string that could potentially be greater
	# than 18 exabytes long, I want your computer!
	[1, 2, 3, 4, 5, 6, 7, 8].each do |lenlen|
		it "encodes a #{lenlen}-byte-length string" do
			expect(TLS::Opaque.new("ohai", 2**(lenlen*8)-1).to_blob).
			  to eq("\0"*(lenlen-1)+"\x04ohai")
		end

		it "decodes a #{lenlen}-byte-length string" do
			blob = "\0"*(lenlen-1) + "\x04ohai"

			expect(TLS::Opaque.from_blob(blob, 2**(lenlen*8)-1)[0].value).
			  to eq("ohai")
		end
	end
end
