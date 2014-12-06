Vagrant.configure("2") do |config|
	config.vm.set_long_hostname = true

	debian_base = <<-EOF
		set -e

		echo "Apt::Install-Recommends 'false';" >/etc/apt/apt.conf.d/02no-recommends
		echo "Acquire::Languages { 'none' };" >/etc/apt/apt.conf.d/05no-languages
		apt-get update
		apt-get -y dist-upgrade

		apt-get -y install locales

		echo "en_AU.UTF-8 UTF-8" >/etc/locale.gen
		echo "en_US.UTF-8 UTF-8" >>/etc/locale.gen
		locale-gen
	EOF

	if ENV['http_proxy']
		debian_base = <<-EOF
			echo "Acquire::http::Proxy \\"#{ENV['http_proxy']}\\";" >/etc/apt/apt.conf.d/50proxy
			#{debian_base}
		EOF
	end

	config.vm.define "log-scratch" do |cfg|
		cfg.vm.box = "wheezy64"

		cfg.vm.hostname = "ctlog.vagrant"

		cfg.vm.provision "shell" do |s|
			s.inline = debian_base
		end
	end
end
