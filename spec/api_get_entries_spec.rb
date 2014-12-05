require_relative './spec_helper'
require 'string_extension'

describe '/v1/get-entries' do
	def app
		slaveapp
	end

	let(:response) do
		get '/get-entries',
		    'start' => '3',
		    'end'   => '7'
	end

	it "returns success" do
		expect(response.status).to eq(200)
	end

	it "returns JSON" do
		expect(response['Content-Type']).to eq("application/json; charset=UTF-8")
	end

	it "sets a long expire header" do
		expect(response["Expires"]).to_not be(nil)
		expect(response["Expires"]).to match(/^[A-Z][a-z]{2}, \d{1,2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$/)
		expect(Time.parse(response["Expires"])).to be_within(5).of(Time.now+(360*86400))
	end

	context "body" do
		let(:body) do
			JSON.parse(response.body)
		end

		it "has an 'entries' key" do
			expect(body).to have_key('entries')
		end

		it "has a list of entries" do
			expect(body['entries']).to be_an(Array)
		end

		it "has exactly the right number of entries" do
			expect(body['entries'].length).to eq(5)
		end

		["PG\xEE\x96m\x04\xF7\xD6\xB0\xD3\"\x8D\x8C\x02O\xCA",
		 "\xDB8\xF7\v'\x9EM\x847\xA1\f\x185\"\xDD\xE1",
		 "IQJ\xEFW\x05\x89\xC8l\x91.F\x1E\x93\xA4L",
		 "\x8E(\x83ZQ\xDEQ\x8A\x85}\xC2\xBA\xC8\x9D\xFEb",
		 "\xCE\xA6\xA8\x98\xB2\xB0\xF0\x8B\xE1\xAB\x9D\x9Esck'"
		].each_with_index do |h, i|
			it "has the right leaf_input in entry #{i}" do
				expect(Digest::MD5.digest(body['entries'][i]['leaf_input'])).to eq(h)
			end
		end

		["C\xDD\xC0\xEFH\x97\xAAJi\xD4\xFE#w.\xDE\x81",
		 "d\xFD&5\x96^n\xE1\\\xE9\xC6\xBA<\x7F\xAF\xB6",
		 "m\x1A\bh!\xB3\xB24\xE1\xBC:-B\x95l\x83",
		 "\x82$\xCDo\xCD\xBFi~\t\xD9\xB2\raD\xAB\r",
		 "\xC4\f\xABFOk\xF3I\"0\x98_\xE1\x13\xBC5"
		].each_with_index do |h, i|
			it "has the right extra_data in entry #{i}" do
				expect(Digest::MD5.digest(body['entries'][i]['extra_data'])).to eq(h)
			end
		end
	end
end
