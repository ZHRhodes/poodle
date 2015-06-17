#!/usr/bin/ruby
#
#  (c) 2009-2010 AmpliaSECURITY
#  Agustin Azubel - aazubel@ampliasecurity.com
#
#  Vaudenay + Rizzo-Duong proof of concept.
#    Decrypt captcha using Vaudenay's cbc-padding-oracle-side-channel,
#    Encrypt captcha using Rizzo-Duong CBC-R technique.
#


require "socket"
include Socket::Constants
 
require 'openssl'
require 'base64'
require 'cgi'

class String
  def to_raw
    "\"%s\"" % split("").map { |b| '\x%02x' % b[0] }.join("")
  end
end


class LocalhostCbcPaddingVulnerableServer
  def initialize
    @socket = nil
  end

  def setup
    @socket = TCPServer::new "127.0.0.1", 8000
    opt = [1].pack "i"
    @socket.setsockopt SOL_SOCKET, SO_REUSEADDR, opt
    @socket.listen 5
  end

  def run
    setup
    loop do 
      client, sockaddr = @socket.accept
      handle client
      client.close
    end
  end 

  def handle client
    request = client.readline

    re = /attack.html/
    tokens = re.match(request)
    if tokens and tokens.length == 1 then
      puts "attack.html request!"
      data = File.open("attack.html", "r").read
      client.write "" +
        "HTTP/1.0 200 OK\r\n" +
        "Content-type: text/html\r\n" +
        "Content-Length: #{data.length}\r\n" +
        "\r\n" +
        "#{data}"
      return
    end

    re = /captcha=(.*) HTTP/
    tokens = re.match(request)
    if !tokens or tokens.length != 2
      re = /securityWord=(.*) HTTP/
      tokens = re.match(request)
      return if !tokens or tokens.length == 0
      captcha = tokens[1]
      puts "captcha: #{captcha}"
      captcha = CGI::unescape captcha
      captcha = Base64.decode64 captcha
      cipher_iv = captcha[0,8]
      ciphertext = captcha[8..-1]
    else
      captcha = tokens[1]
      puts "captcha: #{captcha}"
      captcha = CGI::unescape captcha
      captcha = Base64.decode64 captcha
      cipher_iv = "\x00\x11\x22\x33\x44\x55\x66\x77"
      ciphertext = captcha[0..-1]
    end 
    puts "iv: #{cipher_iv.to_raw}"
    puts "ciphertext: #{ciphertext.to_raw}"

    cipher_key = "\x11secret\x11"

    cipher = OpenSSL::Cipher::Cipher.new "des-cbc"
    cipher.decrypt
    cipher.key = cipher_key
    cipher.iv = cipher_iv
    padding = 0
    cipher.padding = padding 
    begin
      decryptedtext = cipher.update ciphertext
      decryptedtext = cipher.final if padding == 1
      puts "decryptedtext: #{decryptedtext.to_raw}"
      1.upto(8) do |i|
        if decryptedtext[-i, i] == i.chr * i
          data = get_image
          client.write "" +
            "HTTP/1.0 200 OK\r\n" +
            "Content-type: image/jpeg\r\n" +
            "Content-Length: #{data.length}%s\r\n" +
            "\r\n" +
            "#{data}"
          return
        end
      end

      data = "<html>\r\nBAD\r\n</html>"
      client.write "" +
        "HTTP/1.0 200 OK\r\n" +
        "Content-type: text/html\r\n" +
        "Content-length: #{data.length}\r\n"
        "#{data}"
      raise "Invalid padding!"
    rescue Exception => e
      puts "invalid padding! (#{e.to_s})"
    end
  end

  def get_image
    Base64.decode64 "" +
      "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAkGBwgHBgkIBwgKCgkLDRYPDQwM" +
      "DRsUFRAWIB0iIiAdHx8kKDQsJCYxJx8fLT0tMTU3Ojo6Iys/RD84QzQ5Ojf/" +
      "2wBDAQoKCg0MDRoPDxo3JR8lNzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3" +
      "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzf/wAARCABqAHoDASIAAhEBAxEB/8QA" +
      "GwAAAgIDAQAAAAAAAAAAAAAAAAUEBgEDBwL/xAA7EAABBAEDAgMFBwMDAwUA" +
      "AAABAgMEEQUAEiEGMRMiQQcUFVFhIzJCVHGT0RZSgSQzVUNysVNigrLB/8QA" +
      "GQEBAAMBAQAAAAAAAAAAAAAAAAIDBAEF/8QAJBEAAwACAgICAQUAAAAAAAAA" +
      "AAECAxEEIRIxQVFxgZGhsfD/2gAMAwEAAhEDEQA/AO4aNGjQBoGjQNARslPj" +
      "4yE7MmLKI7QBcWEk7RYFmvQXZPoLOtj8hphKlOrSmkqXRIshPcjVQ696nj45" +
      "bmFkRHJAmw1pLSEWtwLtA8NP46P3k9wFJIsA1UZEfOv4uK3JzJitQoD1ILaV" +
      "SFNqQApC1ElJCaoKHNEXzyc+blYsLSt+ycxVeiy5TraHmOkJSsY47HmTsZ4k" +
      "QFW1YW4ssgAg/eSuhx8xWtkjrxhnpJc+AEy5rUFhzYpQrxnLSEKo3uBQoqHo" +
      "BqvdI9Ow4rTEl6G0tamWn2ZS07i2FISVpBP3aXuPFcK/XWp7Ax86x8RhY5DC" +
      "3se86pbY2F2QtJQhJqrKbcs9wSNZp5/lkc+PX2TeHrezo+U6igYzFZKe+5uR" +
      "jyUPJT6ubUqCE/MnckfqfodbcXklOMQI+TWwzlZEYPrioVyKA3UCboFQF651" +
      "kMDiG4s+M3Ifaf8AAVNUZb7ryWCskb1JUo+ZVKB/ERuF885wHUEv+sVysvFD" +
      "eWnhqGylSVJZjoCS86nefVKNnl7lZPp204eROV6Sa/JCocnV9GkuJ6hZzOTk" +
      "M4tCZEGMCl6clf2Ze4+zR/fQ5UQaHA5JNOtaCAaNGjQANZ1gaNAGjRo0AaoX" +
      "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" +
      "A//Z"
  end
end


LocalhostCbcPaddingVulnerableServer.new.run
