# 정부24 자동 로그인 (`govkr_client.py`)

이 프로젝트는 **정부24(Gov.kr)** 사이트에 자동으로 로그인할 수 있도록 도와주는 Python 코드입니다.
**공동인증서** 기반 로그인을 시뮬레이션하고, 실제로 정부24에 **로그인 세션**을 수립해볼 수 있습니다.

---

## ❓ 프로젝트 개요

- **공동인증서**를 사용하여 실제 **정부24** 홈페이지에 로그인할 수 있는 예시 코드입니다.
- PKCS#7 기반 **전자서명**과 **VID 메시지**를 생성하여 서버에 제출함으로써 인증 과정을 모사합니다.
- 실제 **정부24** 서비스 사용 환경과 가장 유사하게 구성되어 있으나, **학습/연구** 목적을 위한 **예시 코드**입니다.

---

## 📂 구성 파일

본 프로젝트에는 다음과 같은 주요 스크립트가 포함됩니다:

1. **`govkr_client.py`**  
   - **클라이언트 측**에서 정부24에 요청을 보내는 **주요 로직**을 담고 있습니다.  
   - 인증서(공개키/개인키)로 PKCS#7 서명과 VID 메시지를 생성하고, **정부24 로그인 요청**을 시도합니다.

2. **`govkr_authenticator.py`**  
   - **서버 측**에서 클라이언트 요청을 **검증**하고, 서명/VID 메시지를 **복호화**하여 인증하는 과정을 **시뮬레이션**합니다.  
   - 테스트 목적으로 작성된 코드이므로, 실제 서버 환경과는 차이가 있을 수 있습니다.

3. **`make_test_cert.py`**  
   - 테스트용 **서버 인증서**(공개키/개인키)를 **자동 생성**하기 위한 스크립트입니다.
   - 실제 **정부24** 서버 인증서가 아닌, **데모** 목적으로 작성되었습니다.

---

추신. 로그인 구현이 끝난 후 아이디 / 비밀번호 로그인으로도 작업이 가능함을 알게 되어 후회중입니다.

## 📌 주요 기능

- **공동 인증서 기반 로그인** (`govkr_client.py`):  
  - `signCert.der`, `signPri.key` 및 개인키 비밀번호를 사용해 RSA 서명 기반 인증을 구현합니다.

- **서버 인증서 테스트 발급** (`make_test_cert.py`):  
  - 테스트용 X.509 서버 인증서를 발급할 수 있습니다.

- **서버 측 검증 시뮬레이션** (`govkr_authenticator.py`):  
  - 클라이언트가 제출한 서명/VID 메시지를 복호화하고, 실제 개인키 소유 여부를 확인하는 과정을 구현합니다.

---

## 🛠️ 설치 방법

이 프로젝트를 사용하려면 필요한 패키지를 설치해야 합니다.

```bash
pip install -r requirements.txt
```

---

## 🚀 govkr_client.py 사용 방법
   1. **인증서 준비**

      - `signCert.der` (서명용 공개 인증서)
      - `signPri.key` (서명용 개인키)
      - `svr_cert.der` (서버측 암호화 인증서, 미기입 시 자동 수집)

   2. **로그인 실행**

      ```bash
      python govkr_client.py
      ```

   3. **인증서 비밀번호 입력**

      - 실행 후, 인증서 비밀번호를 입력하면 자동으로 로그인 시도

   4. **로그인 성공 시 사용자 이름 출력**

      ```text
      사용자 이름: var userNm = "홍길동";
      ```

---

## 🚀 govkr_authenticator.py 사용 방법
   1. **인증서 준비**

      - `signCert.der` (클라이언트 공개 인증서)
      - `signPri.key` (클라이언트 개인키)
      - `test.der` (서버측 공개 인증서)
      - `test.pem` (서버측 개인키)

   2. **시뮬레이션 실행**

      ```bash
      python govkr_authenticator.py
      ```

   3. **인증서 비밀번호 입력**

      - 실행 후, 클라이언트 인증서 비밀번호를 입력하면 자동으로 서버에 로그인 시도

   4. **최종 검증 성공 시 로그 출력**

      ```text
      [Server] 서명 검증 성공! original_data = b'Hello GovKR!'
      [Server] VID randomNum = ~~~~~~
      [Server] 최종 검증 완료 - 로그인 허용!
      ```

---

## ✨ 상세 구현 과정

**로그인시 요구 데이터 확인**
   - 공동인증서 로그인 요청 시, 서버는 서명 정보(xml, pkcs1Msg)와 vidMsg 두 개의 주요 데이터를 요구합니다.
   - 클라이언트는 위에서 생성한 서명 및 vidMsg를 포함한 데이터를 POST 방식으로 전송합니다.
   - AnySign과의 웹소켓 통신을 통해 제공받는 vidMsg에 대한 구현이 핵심적입니다.

**서명 생성**
   - 서명용 인증서와 개인키를 사용하여 고정 데이터에 대해 PKCS#7 서명을 생성합니다.
   - 생성된 서명은 16진수 문자열로 변환되어 로그인 요청 데이터에 포함됩니다.

**고유 난수 값(random_num) 추출**
   - 개인키를 로드하는 과정에서, DER 디코딩을 통해 내부 구조에 포함된 고유 난수 값(random_num)이 추출됩니다.
   - vid 메시지 생성 시, ASN.1 DER 인코딩을 통해 빈 문자열과 함께 BIT STRING 형식으로 포함되어, 메시지의 무결성과 유일성을 보장합니다.

**vid 메시지 생성**
   - ASN.1 DER 구조를 이용해 빈 문자열과 앞서 생성된 random_num을 포함하는 메시지 구조를 생성합니다.
   - 생성된 구조는 SEED/CBC 로 대칭키 암호화를 수행하여 암호문을 생성합니다.
   - 대칭키는 서버 측 인증서의 공개키(RSAES-PKCS1-V1_5)를 이용해 암호화되며, 두 암호문의 결합 후 16진수 문자열로 변환되어 전송됩니다.

**서버 전달 후 서명 검증 (추측)**
   - 전달받은 PKCS#7 서명 데이터에서 공개 인증서 및 서명 데이터를 추출합니다.
   - 서명이 유효한지 확인 후 vidMsg 와 vidMsg 로부터 복호화한 random_num 을 활용해 2차 검증을 시작합니다.
   
**2차 검증 (추측)**
   - 클라이언트의 공개 인증서 정보를 활용해 DB/세션에 저장된 random_num 혹은 vidMsg의 nonce 여부를 비교합니다.
   - 동일/무결하다면 사용자가 실제 개인키 소유자임을 확인할 수 있습니다.
   - 서명 검증만으로도 개인키 소유 사실을 추측할 수 있으나 중간자 공격 대응을 위해 vidMsg를 활용합니다. 
   - 그러나 `govkr_authenticator.py`에선 구현하지 않았습니다.

---

## ⚠️ 주의 사항

- 본 스크립트는 **학술적 연구 및 개인 학습 목적으로 제작**되었으며 **학술적 연구 및 개인 학습 목적으로만 사용**해야 합니다.
- **상업적 용도로의 사용은 엄격히 금지**됩니다.  
- 본 스크립트는 특정 서비스의 정책 변경에 따라 정상적으로 동작하지 않을 수 있습니다.
- 무단 사용 및 부적절한 활용으로 인해 발생하는 문제에 대해 제작자는 책임지지 않습니다.
