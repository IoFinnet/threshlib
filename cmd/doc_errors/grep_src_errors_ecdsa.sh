# ECDSA - Search for error messages in the source code

cd ../..
echo "crypto/vss/feldman_vss.go ( keygen/round_1 )"
head -n 97 crypto/vss/feldman_vss.go | tail -40 | grep -o "Errorf.*" 
echo "----------------"

echo "crypto/zkp/sch/sch.go ( keygen/round_1 )"
head -n 132 crypto/zkp/sch/sch.go | tail -12 | grep -o "errors\..*" 
echo "----------------"

echo "ecdsa/keygen/round_1.go"
grep -no "errors\.New.*" ecdsa/keygen/round_1.go 
echo "----------------"

echo "ecdsa/keygen/round_1.go"
grep -no "errors2\.Wrapf.*" ecdsa/keygen/round_1.go 
echo "----------------"

echo "crypto/zkp/prm/prm.go ( keygen/round_1 )"
head -n 88 crypto/zkp/prm/prm.go | tail -23 | grep -o "Errorf.*" 
echo "----------------"

echo "crypto/ecpoint.go ( keygen/round_1 )"
head -n 216 crypto/ecpoint.go | tail -15 | grep -o "errors\..*" 
echo "----------------"

echo "ecdsa/keygen/round_2.go"
grep -no "errors\.New.*" ecdsa/keygen/round_2.go 
echo "----------------"

echo "ecdsa/keygen/round_3.go"
grep -no "fmt\.Errorf.*" ecdsa/keygen/round_3.go 
echo "----------------"

echo "ecdsa/keygen/round_3.go"
grep -no "errors\.New.*" ecdsa/keygen/round_3.go 
echo "----------------"

echo "ecdsa/keygen/round_4.go"
grep -no "errors\.New.*" ecdsa/keygen/round_4.go 
echo "----------------"

echo "crypto/ecpoint.go ( keygen/round_4 )"
head -n 40 crypto/ecpoint.go | tail -5 | grep -o "fmt\.Errorf.*" 
echo "----------------"

echo "ecdsa/keygen/round_out.go"
grep -no "errors\.New.*" ecdsa/keygen/round_out.go
echo "----------------"

## resharing

echo "ecdsa/resharing/round_1_old_step_1.go"
grep -no "errors\.New.*" ecdsa/resharing/round_1_old_step_1.go
echo "----------------"

echo "ecdsa/resharing/round_1_old_step_1.go"
grep -no "fmt\.Errorf.*" ecdsa/resharing/round_1_old_step_1.go
echo "----------------"

echo "ecdsa/resharing/round_2_new_step_1.go"
grep -no "errors\.New.*" ecdsa/resharing/round_2_new_step_1.go
echo "----------------"

echo "ecdsa/resharing/round_4_new_step_2.go"
grep -no "errors\.New.*" ecdsa/resharing/round_4_new_step_2.go
echo "----------------"

echo "ecdsa/resharing/round_4_new_step_2.go"
grep -no "errors2\.Wrapf.*" ecdsa/resharing/round_4_new_step_2.go
echo "----------------"


## signing

echo "ecdsa/signing/prepare.go"
grep -no "fmt\.Errorf.*" ecdsa/signing/prepare.go
echo "----------------"

echo "ecdsa/signing/presign_1.go"
grep -no "errors\.New.*" ecdsa/signing/presign_1.go
echo "----------------"

echo "ecdsa/signing/presign_1.go"
grep -no "fmt\.Errorf.*" ecdsa/signing/presign_1.go
echo "----------------"

echo "ecdsa/signing/presign_2.go"
grep -no "errors\.New.*" ecdsa/signing/presign_2.go
echo "----------------"

echo "ecdsa/signing/presign_3.go"
grep -no "errors\.New.*" ecdsa/signing/presign_3.go
echo "----------------"

echo "ecdsa/signing/sign_4.go"
grep -no "errors\.New.*" ecdsa/signing/sign_4.go
echo "----------------"

echo "ecdsa/signing/sign_out.go"
grep -no "fmt\.Errorf.*" ecdsa/signing/sign_out.go
echo "----------------"

echo "ecdsa/signing/identification_6.go"
grep -no "fmt\.Errorf.*" ecdsa/signing/identification_6.go
echo "----------------"

echo "ecdsa/signing/identification_6.go"
grep -no "errors\.New.*" ecdsa/signing/identification_6.go
echo "----------------"

echo "ecdsa/signing/identification_7.go"
grep -no "errors\.New.*" ecdsa/signing/identification_7.go
echo "----------------"

cd cmd/doc_errors