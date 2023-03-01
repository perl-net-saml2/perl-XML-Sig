use strict;
use warnings;

use Test::More tests => 1044;
use XML::Sig;
use File::Which;
use Crypt::OpenSSL::Guess;

my ($major, $minor, $letter) = Crypt::OpenSSL::Guess->openssl_version();

my @hash = qw/sha1 sha224 sha256 sha384 sha512 ripemd160/;

# DSA key size determinst the signature length and therfore the signature hashing algorithm
foreach my $key ('t/dsa.private.key', 't/dsa.private-2048.key', 't/dsa.private-3072.key') {
    # DSA Keys with noX509
    foreach my $digalg (@hash) {
        my $sig = XML::Sig->new( {
            digest_hash => $digalg,
            x509        => 0,
            key         => $key,
        } );
        isa_ok( $sig, 'XML::Sig' );

        my $signed = $sig->sign('<foo ID="123"></foo>');
        ok($signed, "XML Signed Sucessfully using $key dsa-$sig->{sig_hash} digest: $digalg");

        $sig = XML::Sig->new( );
        my $is_valid = $sig->verify( $signed );
        ok( $is_valid == 1, "XML::Sig signed Validated using X509Certificate");

        SKIP: {
            skip "xmlsec1 not installed", 2 unless which('xmlsec1');

            skip "xmlsec1 does not support ecdsa-ripemd160", 2 if $sig->{sig_hash} eq 'ripemd160';

            skip "OpenSSL version 3.0.0 through 3.0.7 do not support ripemd160", 2
                if (($major eq '3.0') and ($minor lt 7) and
                    ($sig->{sig_hash} eq 'ripemd160' or $digalg eq 'ripemd160'));

            ok( (open XML, '>', "t/tmp-dsa-$sig->{sig_hash}-nox509-$digalg.xml"), "File t/tmp-dsa-$sig->{sig_hash}-nox509-$digalg.xml opened for write");
            print XML $signed;
            close XML;

            my $verify_response = `xmlsec1 --verify --id-attr:ID "foo" t/tmp-dsa-$sig->{sig_hash}-nox509-$digalg.xml 2>&1`;
            ok( $verify_response =~ m/^OK/, "t/tmp-dsa-$sig->{sig_hash}-nox509-$digalg.xml is verified using xmlsec1" )
                or warn "calling xmlsec1 failed: '$verify_response'\n";
            unlink "t/tmp-dsa-$sig->{sig_hash}-nox509-$digalg.xml";
        }
    }

    # DSA Keys with noX509
    foreach my $digalg (@hash) {
        my $sig = XML::Sig->new( {
            digest_hash => $digalg,
            x509        => 1,
            key         => $key,
        } );
        isa_ok( $sig, 'XML::Sig' );

        my $signed = $sig->sign('<foo ID="123"></foo>');
        ok($signed, "XML Signed Sucessfully using $key dsa-$sig->{sig_hash} digest: $digalg");

        $sig = XML::Sig->new( );
        my $is_valid = $sig->verify( $signed );
        ok( $is_valid == 1, "XML::Sig signed Validated using X509Certificate");

        SKIP: {
            skip "xmlsec1 not installed", 2 unless which('xmlsec1');

            skip "openssl 3+ does not support ripemd160 digests or signatures",
                2 if ($major ge 3 && ($digalg eq 'ripemd160' || $sig->{sig_hash} eq 'ripemd160'));

            skip "OpenSSL version 3.0.0 through 3.0.7 do not support ripemd160", 2
                if (($major eq '3.0') and ($minor lt 7) and
                    ($sig->{sig_hash} eq 'ripemd160' or $digalg eq 'ripemd160'));

            ok( (open XML, '>', "t/tmp-dsa-$sig->{sig_hash}-x509-$digalg.xml"), "File t/tmp-dsa-$sig->{sig_hash}-x509-$digalg.xml opened for write");
            print XML $signed;
            close XML;

            my $verify_response = `xmlsec1 --verify --id-attr:ID "foo" --pubkey-cert-pem t/dsa.public.pem --trusted-pem t/dsa.public.pem t/tmp-dsa-$sig->{sig_hash}-x509-$digalg.xml 2>&1`;
            ok( $verify_response =~ m/^OK/, "t/tmp-dsa-$sig->{sig_hash}-x509-$digalg.xml is verified using xmlsec1" )
                or warn "calling xmlsec1 failed: '$verify_response'\n";
            if ($verify_response =~ m/^OK/) {
                unlink "t/tmp-dsa-$sig->{sig_hash}-x509-$digalg.xml";
            } else{
                print $signed;
                die;
            }
        }
    }
}

foreach my $sigalg (@hash) {
    # RSA Keys with no X509
    foreach my $digalg (@hash) {
        my $sig = XML::Sig->new( {
            digest_hash    => $digalg,
            sig_hash    => $sigalg,
            key         => 't/rsa.private.key',
        } );
        isa_ok( $sig, 'XML::Sig' );

        my $signed = $sig->sign('<foo ID="123"></foo>');
        ok($signed, "XML Signed Successfully using rsa-$sigalg - no X509 digest: $digalg");

        $sig = XML::Sig->new( );
        my $is_valid = $sig->verify( $signed );
        ok( $is_valid == 1, "XML::Sig signed Validated -no X509");

        SKIP: {
            skip "xmlsec1 not installed", 2 unless which('xmlsec1');

            skip "OpenSSL version 3.0.0 through 3.0.7 do not support ripemd160", 2
                if (($major eq '3.0') and ($minor lt 7) and
                    ($sigalg eq 'ripemd160' or $digalg eq 'ripemd160'));

            ok( (open XML, '>', "t/tmp-rsa-$sigalg-nox509-$digalg.xml"), "File opened for write");
            print XML $signed;
            close XML;

            my $verify_response = `xmlsec1 --verify --pubkey-cert-pem t/rsa.cert.pem --untrusted-pem t/intermediate.pem --trusted-pem t/cacert.pem --id-attr:ID "foo" t/tmp-rsa-$sigalg-nox509-$digalg.xml 2>&1`;
            ok( $verify_response =~ m/^OK/, "t/tmp-rsa-$sigalg-nox509-$digalg.xml RSA is verified using xmlsec1 - no X509" )
                or warn "calling xmlsec1 failed: '$verify_response'\n";
            unlink "t/tmp-rsa-$sigalg-nox509-$digalg.xml";

       }
    }

    # RSA Keys with X509
    foreach my $digalg (@hash) {
        my $sig = XML::Sig->new( {
            digest_hash    => $digalg,
            sig_hash    => $sigalg,
            x509        => 1,
            key         => 't/rsa.private.key',
            cert        => 't/rsa.cert.pem'
        } );
        isa_ok( $sig, 'XML::Sig' );

        my $signed = $sig->sign('<foo ID="123"></foo>');
        ok($signed, "XML Signed Successfully using rsa-$sigalg, digest: $digalg");

        $sig = XML::Sig->new( );
        my $is_valid = $sig->verify( $signed );
        ok( $is_valid == 1, "XML::Sig signed Validated");

        SKIP: {
            skip "xmlsec1 not installed", 2 unless which('xmlsec1');

            skip "OpenSSL version 3.0.0 through 3.0.7 do not support ripemd160", 2
                if (($major eq '3.0') and ($minor lt 7) and
                    ($sigalg eq 'ripemd160' or $digalg eq 'ripemd160'));

            ok( (open XML, '>', "t/tmp-rsa-$sigalg-x509-$digalg.xml"), "File opened for write");
            print XML $signed;
            close XML;

            my $verify_response = `xmlsec1 --verify --pubkey-cert-pem t/rsa.cert.pem --untrusted-pem t/intermediate.pem --trusted-pem t/cacert.pem --id-attr:ID "foo" t/tmp-rsa-$sigalg-x509-$digalg.xml 2>&1`;
            ok( $verify_response =~ m/^OK/, "t/tmp-rsa-$sigalg-x509-$digalg.xml RSA is verified using xmlsec1" )
                or warn "calling xmlsec1 failed: '$verify_response'\n";
            unlink "t/tmp-rsa-$sigalg-x509-$digalg.xml";

        }
    }

    # ECDSA based keys with X509
    foreach my $digalg (@hash) {
        my $sig = XML::Sig->new( {
                    x509 => 1,
                    digest_hash => $digalg,
                    sig_hash    => $sigalg,
                    key => 't/ecdsa.private.pem',
                    cert => 't/ecdsa.public.pem' } );
        isa_ok( $sig, 'XML::Sig' );

        my $signed = $sig->sign('<foo ID="123"></foo>');
        ok($signed, "XML Signed Successfully using ecdsa-$sigalg, digest: $digalg");

        $sig = XML::Sig->new( );
        my $is_valid = $sig->verify( $signed );
        ok( $is_valid == 1, "XML::Sig signed Validated using X509Certificate");

        SKIP: {
            skip "xmlsec1 not installed", 2 unless which('xmlsec1');

            skip "xmlsec1 does not support ecdsa-ripemd160", 2 if $sigalg eq 'ripemd160';

            skip "OpenSSL version 3.0.0 through 3.0.7 do not support ripemd160", 2
                if (($major eq '3.0') and ($minor lt 7) and
                    ($sigalg eq 'ripemd160' or $digalg eq 'ripemd160'));

            ok( (open XML, '>', "t/tmp-ecdsa-$sigalg-x509-$digalg.xml"), "File opened for write");
            print XML $signed;
            close XML;

            my $verify_response = `xmlsec1 --verify --trusted-pem t/ecdsa.public.pem --id-attr:ID "foo" t/tmp-ecdsa-$sigalg-x509-$digalg.xml 2>&1`;
            ok( $verify_response =~ m/^OK/, "ECDSA Response is verified using xmlsec1" )
                or warn "calling xmlsec1 failed: '$verify_response'\n";
            if ($verify_response =~ m/^OK/) {
                unlink "t/tmp-ecdsa-$sigalg-x509-$digalg.xml";
            } else{
                print $signed;
                die;
            }
        }

        $sig = XML::Sig->new( { key => 't/ecdsa.private.pem' } );
        isa_ok( $sig, 'XML::Sig' );

        $signed = $sig->sign('<foo ID="123"></foo>');
        ok($signed, "XML Signed Sucessfully using ecdsa key");

        $sig = XML::Sig->new( );
        $is_valid = $sig->verify( $signed );
        ok( $is_valid == 1, "XML::Sig signed Validated using ECDSAKey");
    }

    # ECDSA based keys with no X509
    foreach my $digalg (@hash) {
        my $sig = XML::Sig->new( {
                    digest_hash => $digalg,
                    sig_hash    => $sigalg,
                    key => 't/ecdsa.private.pem',
                    x509 => 0,
                    }
                );
        isa_ok( $sig, 'XML::Sig' );

        my $signed = $sig->sign('<foo ID="123"></foo>');
        ok($signed, "XML Signed Sucessfully using ecdsa-$sigalg, digest: $digalg");

        $sig = XML::Sig->new( );
        my $is_valid = $sig->verify( $signed );
        ok( $is_valid == 1, "XML::Sig signed Validated using X509Certificate");

        $sig = XML::Sig->new( { key => 't/ecdsa.private.pem' } );
        isa_ok( $sig, 'XML::Sig' );

        $signed = $sig->sign('<foo ID="123"></foo>');
        ok($signed, "XML Signed Sucessfully using ecdsa key");

        $sig = XML::Sig->new( );
        $is_valid = $sig->verify( $signed );
        ok( $is_valid == 1, "XML::Sig signed Validated using ECDSAKey");
    }
}

done_testing;
