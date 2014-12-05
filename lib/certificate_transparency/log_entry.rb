class CertificateTransparency::LogEntry
	attr_accessor :leaf_input, :chain

	def initialize(json = nil)
		if json
			data = JSON.parse(json)
			@leaf_input = CertificateTransparency::MerkleTreeLeaf.from_blob((data['leaf_input'] || "").unbase64)
			@chain      = (data['chain'] || []).map { |h| h.unbase64 }
		end
	end

	def to_json
		if @leaf_input.nil?
			raise RuntimeError, "Cannot encode: no leaf_input"
		end
		if @chain.nil?
			raise RuntimeError, "Cannot encode: no chain"
		end

		{:leaf_input => @leaf_input.to_blob.base64,
		 :chain => chain.map { |h| h.base64 }
		}.to_json
	end

	def to_s
		@leaf_input.to_blob
	end
end
