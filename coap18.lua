--[[
Copyright (c) 2014, Oliver Kleine, Institute of Telematics, University of Luebeck
All rights reserved

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
following conditions are met:

 - Redistributions of source code must retain the above copyright notice, this list of conditions and the following
    disclaimer.

 - Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
    following disclaimer in the documentation and/or other materials provided with the distribution.

 - Neither the name of the University of Luebeck nor the names of its contributors may be used to endorse or promote
    products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
]]

do
   coapProto = Proto("coap18","CoAP (RFCs 7252, RFC 7641, and blockwise transfer)")

   --message types
   local types = {
      [0]="CON",
      [1]="NON",
      [2]="ACK",
      [3]="RST"
   }
   
   --message codes
   local codes = {
      [0]="EMPTY",

      --request codes
      [1]="GET",
      [2]="POST",
      [3]="PUT",
      [4]="DELETE",

      --response codes
      [65]="2.01 Created",
      [66]="2.02 Deleted",
      [67]="2.03 Valid",
      [68]="2.04 Changed",
      [69]="2.05 Content",
      [95]="2.31 Continue",
      [128]="4.00 Bad Request",
      [129]="4.01 Unauthorized",
      [130]="4.02 Bad Option",
      [131]="4.03 Forbidden",
      [132]="4.04 Not Found",
      [133]="4.05 Method Not Allowed",
      [134]="4.06 Not Acceptable",
      [136]="4.08 Request Entitiy Incomplete",
      [140]="4.12 Precondition Failed",
      [141]="4.13 Request Entity Too Large",
      [143]="4.15 Unsupported Content-Format",
      [160]="5.00 Internal Server Error",
      [161]="5.01 Not Implemented",
      [162]="5.02 Bad Gateway",
      [163]="5.03 Service Unavailable",
      [164]="5.04 Gateway Timeout",
      [165]="5.05 Proxying Not Supported"
   }

   -- human readable names for predefined content formats
   local formatStrings = {
      [0]="text/plain; charset=utf-8",
      [40]="application/link-format",
      [41]="application/xml",
      [42]="application/octet-stream",
      [47]="application/exi",
      [50]="application/json"
   }

   -- decoded blocksizes (from SZX)
   local blocksize = {
         [0] = "16 Byte",
         [1] = "32 Byte",
         [2] = "64 Byte",
         [3] = "128 Byte",
         [4] = "256 Byte",
         [5] = "512 Byte",
         [6] = "1024 Byte"
   }
   
   -- more blocks expected
   local moreblocks = {
       [0] = "false",
       [1] = "true"
   }

   -- create fields
   local f = coapProto.fields

   -- header fields
   f.version = ProtoField.uint8 ("coap18.version", "Version", nil, nil, 0xC0)
   f.type = ProtoField.uint8 ("coap18.type", "Type", nil, types, 0x30)
   f.tkl = ProtoField.uint8 ("coap18.tkl", "Token Length", nil, nil, 0x0F)
   f.code = ProtoField.uint8 ("coap18.code", "Code", nil, codes)
   f.msgid = ProtoField.uint16 ("coap18.msgid", "Message ID (decimal)", base.DEC)
   f.token = ProtoField.bytes ("coap18.token", "Token")

   -- core protocol option fields
   f.options = ProtoField.string("coap18.options", "Options")
   f.ifmatch = ProtoField.bytes("coap18.options.ifmatch", "If-Match (No. 1)")
   f.urihost = ProtoField.string("coap18.options.urihost", "URI-Host (No. 3)")
   f.etag = ProtoField.bytes("coap18.options.etag", "ETAG (No. 4)")
   f.ifnonematch = ProtoField.string("coap18.options.ifnonematch", "If-None-Match (No. 5)")
   f.uriport = ProtoField.uint16("coap18.options.uriport", "URI-Port (No. 7)") 
   f.locationpath = ProtoField.string("coap18.options.locationpath", "Location Path (No. 8)")
   f.uripath = ProtoField.string("coap18.options.uripath", "URI-Path (No. 11)")
   f.contentformat = ProtoField.uint16("coap18.options.contentformat", "Content-Format (No. 12)", nil, formatStrings)
   f.maxage = ProtoField.uint32("coap18.options.maxage", "Max-Age (No. 14)")
   f.uriquery = ProtoField.string("coap18.options.uriquery", "URI-Query (No. 15)")
   f.accept = ProtoField.uint16("coap18.options.accept", "Accept (No. 17)", nil, formatStrings)
   f.locationquery = ProtoField.string("coap18.options.locationquery", "Location-Query (No. 20)")
   f.proxyuri = ProtoField.string("coap18.options.proxyuri", "Proxy-URI (No. 35)")
   f.proxyscheme = ProtoField.string("coap18.options.proxyscheme", "Proxy-Scheme (No. 39)")
   f.size1 = ProtoField.uint32("coap18.options.size1", "Size1 (No. 60)")

   -- observe extension fields
   f.observe = ProtoField.uint24("coap18.options.observe", "Observe (No. 6)")
   
   -- blockwise transfer extension fields
   f.block2 = ProtoField.bytes("coap18.options.block2", "Block2 (No. 23)")
   f.block2num24 = ProtoField.uint24("coap18.options.block2.num", "NUM", nil, nil, 0xFFFFF0)
   f.block2num16 = ProtoField.uint16("coap18.options.block2.num", "NUM", nil, nil, 0xFFF0)
   f.block2num8 = ProtoField.uint8("coap18.options.block2.num", "NUM", nil, nil, 0xF0)
   f.block2m = ProtoField.uint8("coap18.options.block2.m", "M", nil, moreblocks, 0x08)
   f.block2szx = ProtoField.uint8("coap18.options.blok2.szx", "SZX", nil, blocksize, 0x07)

   f.block1 = ProtoField.bytes("coap18.options.block1", "Block1 (No. 27)")
   f.block1num24 = ProtoField.uint24("coap18.options.block1.num", "NUM", nil, nil, 0xFFFFF0)
   f.block1num16 = ProtoField.uint16("coap18.options.block1.num", "NUM", nil, nil, 0xFFF0)
   f.block1num8 = ProtoField.uint8("coap18.options.block1.num", "NUM", nil, nil, 0xF0)
   f.block1m = ProtoField.uint8("coap18.options.block1.m", "M", nil, moreblocks, 0x08)
   f.block1szx = ProtoField.uint8("coap18.options.block1.szx", "SZX", nil, blocksize, 0x07)

   f.size2 = ProtoField.uint32("coap18.options.size2", "Size2 (No. 28)")

   -- the message payload field
   f.payload = ProtoField.string("coap18.payload", "Content")
   

   --function to dissect the bytes
   function coapProto.dissector(buffer, pinfo, tree)
      pinfo.cols.protocol = "CoAP (RFC 7252)"
      local protoTree = tree:add(coapProto, buffer(), "Constrained Application Protocol")

      local isRequest = not ((buffer(1, 1):uint() > 4))

      protoTree:add(f.version, buffer(0, 1))
      protoTree:add(f.type, buffer(0, 1))
      protoTree:add(f.tkl, buffer(0, 1))
      protoTree:add(f.code, buffer(1, 1))
      protoTree:add(f.msgid, buffer(2, 2))

      local tokenLength = bit32.band(buffer(0, 1):uint(), 0x0F)
      local index = 4
      
      -- read the token (if any)
      if tokenLength > 0 and tokenLength <= 8 then
         protoTree:add(f.token, buffer(index, tokenLength))
      end
      index = index + tokenLength

      --dissect options
      if(index < buffer:len()) then
         local endOfOptions = buffer(index, 1):uint() == 0xFF
         if (not endOfOptions) then
            local optionsTree = protoTree:add(f.options)
            local lastOption = 0
         
            -- loop over options until buffer ends or end-of-options marker is reached
            while (index < buffer:len()) and (not endOfOptions) do

               local optionHeader = buffer(index, 1):uint()
               index = index + 1

               local optionDelta = bit32.rshift(bit32.band(optionHeader, 0xF0), 4)
               local optionLength = bit32.band(optionHeader, 0x0F)

               -- check for end-of-options marker, i.e. there are no more options
               if (optionHeader == 0xFF) then
                  endOfOptions = true
                  optionLength = 0

               -- there is another option
               else
                  local optionHeaderLength = 1

                  -- check if extended option delta is used
                  if (optionDelta == 0x0D) then
                     optionDelta = buffer(index, 1):uint() + 13
                     index = index + 1
                     optionHeaderLength = optionHeaderLength + 1

                  elseif (optionDelta == 0x0E) then
                     optionDelta = buffer(index, 2):uint() + 269
                     index = index + 2
                     optionHeaderLength = optionHeaderLength + 2

                  end

                  -- check if extended option length is used
                  if (optionLength == 0x0D) then
                     optionLength = buffer(index, 1):uint() + 13
                     index = index + 1
                     optionHeaderLength = optionHeaderLength + 1

                  elseif (optionLength == 0x0E) then
                     optionLength = buffer(index, 2):uint() + 269
                     index = index + 2
                     optionHeaderLength = optionHeaderLength + 2
                  end

                  local optionNumber = lastOption + optionDelta
                  local optionStart = index
               
                  local minOptionLength
                  local maxOptionLength
                  local optionSubTree

                  -- If-Match
                  if (optionNumber == 1) then
                     optionSubTree = optionsTree:add(f.ifmatch, buffer(optionStart, optionLength))

                     minOptionLength = 0
                     maxOptionLength = 8
                  
                  -- URI-Host
                  elseif (optionNumber == 3) then
                     optionSubTree = optionsTree:add(f.urihost, buffer(optionStart, optionLength))

                     minOptionLength = 1
                     maxOptionLength = 255

                  -- ETAG
                  elseif (optionNumber == 4) then
                     optionSubTree = optionsTree:add(f.etag, buffer(optionStart, optionLength))

                     minOptionLength = 1
                     maxOptionLength = 8

                  -- If-None-Match
                  elseif (optionNumber == 5) then
                     optionSubTree = optionsTree:add(f.ifnonematch, "<EMPTY>")

                     minOptionLength = 0
                     maxOptionLength = 0

                  -- Observe
                  elseif (optionNumber == 6) then
                     print("Option No. 6")
                     if(optionLength == 0) then
                        optionSubTree = optionsTree:add(f.observe, 0)
                     else
                        optionSubTree = optionsTree:add(f.observe, buffer(optionStart, optionLength))
                     end

                     minOptionLength = 0
                     maxOptionLength = 3

                  -- URI-Port
                  elseif (optionNumber == 7) then
                     if(optionLength == 0) then
                        optionSubTree = optionsTree:add(f.uriport, 0)
                     else
                        optionSubTree = optionsTree:add(f.uriport, buffer(optionStart, optionLength))
                     end

                     minOptionLength = 0
                     maxOptionLength = 2
   
                  -- Location-Path
                  elseif (optionNumber == 8) then
                     optionSubTree = optionsTree:add(f.locationpath, buffer(optionStart, optionLength))

                     minOptionLength = 0
                     maxOptionLength = 255

                  -- URI-Path
                  elseif (optionNumber == 11) then
                     optionSubTree = optionsTree:add(f.uripath, buffer(optionStart, optionLength))

                     minOptionLength = 0
                     maxOptionLength = 255

                  -- Content-Format
                  elseif (optionNumber == 12) then
                     if(optionLength == 0) then
                        optionSubTree = optionsTree:add(f.contentformat, 0)
                     else
                        optionSubTree = optionsTree:add(f.contentformat, buffer(optionStart, optionLength))
                     end

                     minOptionLength = 0
                     maxOptionLength = 2

                  -- Max-Age
                  elseif (optionNumber == 14) then
                     if(optionLength == 0) then
                        optionSubTree = optionsTree:add(f.maxage, 0)
                     else
                        optionSubTree = optionsTree:add(f.maxage, buffer(optionStart, optionLength))
                     end

                     minOptionLength = 0
                     maxOptionLength = 4

                  -- URI-Query
                  elseif (optionNumber == 15) then
                     optionSubTree = optionsTree:add(f.uriquery, buffer(optionStart, optionLength))
                     
                     minOptionLength = 0
                     maxOptionLength = 255

                  -- Accept
                  elseif (optionNumber == 17) then
                     if(optionLength == 0) then
                        optionSubTree = optionsTree:add(f.accept, 0)
                     else
                        optionSubTree = optionsTree:add(f.accept, buffer(optionStart, optionLength))
                     end

                     minOptionLength = 0
                     maxOptionLength = 2
   
                  -- Location-Query
                  elseif (optionNumber == 20) then
                     optionSubTree = optionsTree:add(f.locationquery, buffer(optionStart, optionLength))

                     minOptionLength = 0
                     maxOptionLength = 255

                  -- Block2
                  elseif (optionNumber == 23) then
                     optionSubTree = optionsTree:add(f.block2, buffer(optionStart, optionLength))
                     if(optionLength == 0) then
                        optionSubTree:add(f.block2num8, 0)
                        optionSubTree:add(f.block2m, 0)
                        optionSubTree:add(f.block2szx, 0)
                     elseif(optionLength > 0 and (not (optionLength > 3))) then
                        if (optionLength == 1) then
                           optionSubTree:add(f.block2num8, buffer(optionStart, optionLength))
                        elseif (optionLength == 2) then
                           optionSubTree:add(f.block2num16, buffer(optionStart, optionLength))
                        elseif(optionLength == 3) then
                           optionSubTree:add(f.block2num24, buffer(optionStart, optionLength))
                        end
                        
                        optionSubTree:add(f.block2m, buffer(optionStart, optionLength))
                        optionSubTree:add(f.block2szx, buffer(optionStart, optionLength))
                     end

                     minOptionLength = 0
                     maxOptionLength = 3

                  -- Block1
                  elseif (optionNumber == 27) then
                     optionSubTree = optionsTree:add(f.block1, buffer(optionStart, optionLength))
                     if(optionLength == 0) then
                        optionSubTree:add(f.block1num8, 0)
                        optionSubTree:add(f.block1m, 0)
                        optionSubTree:add(f.block1szx, 0)

                     elseif(optionLength > 0 and (not (optionLength > 4))) then
                        if (optionLength == 1) then
                           optionSubTree:add(f.block1num8, buffer(optionStart, optionLength))
                        elseif (optionLength == 2) then
                           optionSubTree:add(f.block1num16, buffer(optionStart, optionLength))
                        elseif(optionLength == 1) then
                           optionSubTree:add(f.block2num24, buffer(optionStart, optionLength))
                        end

                        optionSubTree:add(f.block1m, buffer(optionStart, optionLength))
                        optionSubTree:add(f.block1szx, buffer(optionStart, optionLength))
                     end

                     minOptionLength = 0
                     maxOptionLength = 3

                  -- Size2
                  elseif (optionNumber == 28) then
                     optionSubTree = optionsTree:add(f.size2, buffer(optionStart, optionLength))

                     minOptionLength = 0
                     maxOptionLength = 4
                  
                  -- Proxy-URI
                  elseif (optionNumber == 35) then
                     optionSubTree = optionsTree:add(f.proxyuri, buffer(optionStart, optionLength))

                     minOptionLength = 1
                     maxOptionLength = 1034

                  -- Proxy-Scheme
                  elseif (optionNumber == 39) then
                     optionSubTree = optionsTree:add(f.proxyscheme, buffer(optionStart, optionLength))
                  
                     minOptionLength = 1
                     maxOptionLength = 255

                  -- Size1
                  elseif (optionNumber == 60) then
                     if(optionLength == 0) then
                        optionSubTree = optionsTree:add(f.size1, 0)
                     else
                        optionSubTree = optionsTree:add(f.size1, buffer(optionStart, optionLength))
                     end

                     minOptionLength = 0
                     maxOptionLength = 4

                  -- Unknown Option
                  else
                     optionsTree:add(buffer(optionStart, optionLength), "Unkown Option No. " .. optionNumber)

                     minOptionLength = 0
                     maxOptionLength = 65536
                  end

                  -- Check for option value length constraints
                  if (optionLength < minOptionLength or optionLength > maxOptionLength) then
                     optionSubTree:add_expert_info(PI_PROTOCOL, PI_ERROR, "Option value length (" .. optionLength .. ") out of allowed range (min: " .. minOptionLength .. ", max: " .. maxOptionLength ..")")
                  end
                  
            
                  lastOption = optionNumber
               end

               
               index = index + optionLength
            end
         end
      end

      -- if there is more data available, consider this the payload
      if index < buffer:len() then
         protoTree:add(f.payload, buffer(index, buffer:len() - index))
      end

   end

   -- load the udp.port table
   udp_table = DissectorTable.get("udp.port")

   -- register CoAP protocol to handle udp port 5683
   udp_table:add(5683, coapProto)
   
end