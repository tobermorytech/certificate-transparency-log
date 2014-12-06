class Time
	def to_ms
		(self.to_f*1000).round
	end

	def self.from_ms(ms)
		Time.at(ms / 1000.0)
	end
end
