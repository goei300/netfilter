# netfilter

## Skeleton flow 
 netfilter_queue를 통해 패킷을 수신하고, 해당 패킷의 ip header 영역의 address를 buffer에 저장한다.


## Objective
 해당 buffer를 통해 HTTP 프로토콜 패킷인지 검증 후, host가 유해 사이트(argument)인지 확인 한 다음 유해 사이트일 시 패킷을 drop하고 아닐 시 accept하는 동작을 구현한다. 

 
## 헤더 분석

### IP header & TCP header
 ![image](https://github.com/goei300/netfilter/assets/107453711/9a5a6baf-10fc-48f9-8bb2-758d94dba178)
 
 위의 경우에는 직접 세보면 20 bytes.  -> 1
 패킷내에서 ip header의 length를 보여주는 부분은 1st byte의 lower 4bits * 4이다.
 0x45 & 0x0F = 5, 즉 5 * 4 = 20이다.  -> 2
 1=2 일치! 실제로 일치하는거 확인.  => real ip header start address 확인.

 TCP의 경우에도 13th Byte의 higher 4bits * 4이다.
 따라서 0x50 >> 4 & 0x0F * 4 = 0x05 *4 =20이다.
 따라서 HTTP start addr = buf + 40 이다.
 
### HTTP

![image](https://github.com/goei300/netfilter/assets/107453711/5550d018-d29d-49ec-838f-94428fec6014)

 Host 필드는 Method 필드 다음 나오는 것으로 확인.
 각 필드마다 특이점은 끝이 0d 0a, 즉 CRLF로 끝나는 것으로 확인됨.
 따라서 이 구분자를 통해 각 필드를 구분하고 value를 받아는 것으로 구현
 
![image](https://github.com/goei300/netfilter/assets/107453711/7f03eceb-e005-4cd4-987e-422863dc3fc3)

 Host영역에서는 실제 값은 start addr + 6 부터 시작되는 것을 확인.
 따라서 host_value = start addr + 6 에서 부터 0d 0a 직전 으로 저장하도록 함.


 


