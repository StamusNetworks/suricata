FROM debian:jessie

run echo "deb http://ftp.debian.org/debian jessie-backports main" > /etc/apt/sources.list.d/jessie-backports.list

run DEBIAN_FRONTEND=noninteractive apt-get update -qy && \
    apt-get install -y dpkg devscripts git python-dev autoconf automake \
    autopoint autotools-dev binutils bsdmainutils build-essential \
    bzip2 cpp cpp-4.9 debhelper dh-autoreconf dpkg-dev file g++ g++-4.9 \
    gcc gcc-4.9 gettext gettext-base groff-base intltool-debian libasan1 \
    libasprintf0c2 libatomic1 libc-dev-bin libc6-dev libcap-ng-dev libcap-ng0 \
    libcilkrts5 libcloog-isl4 libcroco3 libdpkg-perl libexpat1 libffi6 \
    libgcc-4.9-dev libgcrypt20-dev libgdbm3 libglib2.0-0 libgmp-dev libgmp10 \
    libgmpxx4ldbl libgnutls-deb0-28 libgnutls-openssl27 libgnutls28-dev \
    libgnutlsxx28 libgomp1 libgpg-error-dev libhogweed2 libisl10 libitm1 \
    libjansson-dev libjansson4 liblsan0 libltdl-dev libltdl7 libluajit-5.1-2 \
    libluajit-5.1-common libluajit-5.1-dev libmagic-dev libmagic1 libmnl0 \
    libmpc3 libmpfr4 libnet1 libnet1-dev libnetfilter-queue-dev \
    libnetfilter-queue1 libnettle4 libnfnetlink-dev libnfnetlink0 libnspr4 \
    libnspr4-dev libnss3 libnss3-dev libp11-kit-dev libp11-kit0 libpcap-dev \
    libpcap0.8 libpcap0.8-dev libpcre3-dev libpcrecpp0 libpipeline1 \
    libprelude-dev libprelude2 libpython-stdlib libpython2.7-minimal \
    libpython2.7-stdlib libquadmath0 libsigsegv2 libsqlite3-0 libssl1.0.0 \
    libstdc++-4.9-dev libtasn1-6 libtasn1-6-dev libtimedate-perl libtool \
    libtsan0 libubsan0 libunistring0 libxml2 libyaml-0-2 libyaml-dev \
    linux-libc-dev m4 make man-db mime-support nettle-dev patch perl \
    perl-modules pkg-config po-debconf python python-minimal python2.7 \
    python2.7-minimal xz-utils zlib1g-dev build-essential clang libhiredis-dev \
    curl 

run DEBIAN_FRONTEND=noninteractive apt-get update -qy && \
    apt-get install -y libgeoip-dev

run DEBIAN_FRONTEND=noninteractive apt-get update -qy && \
    apt-get install -y libhyperscan-dev libhyperscan4
    
run curl https://sh.rustup.rs -sSf | sh -s -- -y
env PATH=/root/.cargo/bin:$PATH

run echo 'DEBUILD_DPKG_BUILDPACKAGE_OPTS="-us -uc -I -i"' > /root/.devscripts
run echo 'DEBUILD_LINTIAN_OPTS="-i -I --show-overrides"' >> /root/.devscripts
