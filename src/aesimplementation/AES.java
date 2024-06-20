/*
 * COSC 620 - Assignment GF1
 * Nov 10th 2016
 */

package aesimplementation;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

/**
 *
 * @author Ibrahim Ali Khan
 */
class AES {
    
    private static int polynomial;
//    private static final String s_box="637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16";
//    private static final String s_box_inverse="52096ad53036a538bf40a39f81f3d7fb7ce339829b2fff87348e4344c4dee9cb547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd12572f8f664b6689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d8490d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af41fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cefa0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d";
    private static final String mat_mixCol="02030101010203010101020303010102";
    private static final String mat_mixCol_inverse="0e0b0d09090e0b0d0d090e0b0b0d090e";
    private int block_size, total_rounds, total_aess=0;
    private String text_plain, text_plainn="19a09ae93df4c6f8e3e28d48be2b2a08", text_cipher="";
    private static List S_Box, Rcon, RoundKeys;
    private char mode;
    
    public static void main(String[] args) {
//        Object[] obj;
//        AES aes = new AES(128);
        Object[] obj = AES.readFromFile("input.txt");
        int poly = Integer.parseInt(((String)obj[0]),2);
        String key = (String) obj[1];
        String pt = (String) obj[2];
        String ct = (String) obj[3];
        
        AES aes = new AES(128, poly, key);
        String result = "";
        result = aes.Encryption(pt)+"\n";
        result = result.concat(aes.Decryption(ct)+"\n");
        AES.writeToFile(result);
        
//        System.out.println("Table = "+aes.GetFromTable("d4", "02"));
//        System.out.println("Multiply = "+aes.Multiply("02030101", "d4bf5d30"));
//        System.out.println("Multiply Decryption = "+aes.MultiplyDecryption("0e0b0d09", "112233fb"));
//        System.out.println("Multiply Decryption = "+aes.MultiplyDecryption("090e0b0d", "112233fb"));
//        System.out.println("Multiply Decryption = "+aes.MultiplyDecryption("0d090e0b", "112233fb"));
//        System.out.println("Multiply Decryption = "+aes.MultiplyDecryption("0b0d090e", "112233fb"));
        
//        AES aes = new AES(128, 283, "2b28ab097eaef7cf15d2154f16a6883c");
//        String s = aes.Encryption("3243f6a8885a308d313198a2e0370734");
//        System.out.println("After Encryption = "+s);
//        s = aes.Decryption(s);
//        System.out.println("After Decryption = "+s);
        
//        AES aes = new AES(128, 283, "2b28ab097eaef7cf15d2154f16a6883c");
//        String s = aes.Decryption("3925841d02dc09fbdc118597196a0b32");
//        System.out.println("After Decryption = "+s);
        
//        AES aes = new AES(128, 283, "2b28ab097eaef7cf15d2154f16a6883c");
//        String s = aes.Encryption("00112233445566778899aabbccddeeff");
//        System.out.println(s);
//        s = aes.Decryption(s);
//        System.out.println(s);
        
//        for (int i = 0; i < helper.table_14.length; i++) {
//            String hex = Integer.toHexString(i);
//            if(hex.length() < 2) hex = "0" + hex;
//            int res1 = Integer.parseInt(aes.GetFromTable("0e", hex), 16);
//            int res2 = helper.table_14[i];
//            if(res1 != res2){
//                System.out.println(res1+" "+res2);
////                while(true){
////                    System.out.println("res1 = "+res1+" res2 = "+res2);
////                }
//            }
//            System.out.println(helper.table_3[128]);
//            
//        }
    }
    
    /*
    ** Default Constructor
    ** Calls the first method to properly setup initialization for AES with 
    ** dynamic polynomial for Substitution Bytes
    **
    ** @param Block_sizes
    ** size of a block
    **
    ** @param poly
    ** given polynomial
    **
    ** @param key
    ** given key
    **
    */
    public AES(int Block_sizes, int poly, String key){
        initVars(Block_sizes, poly, key);
    }
    
    /*
    ** Default Constructor 2
    ** Calls the first method to properly setup initialization for AES
    **
    ** @param Block_size
    ** size of block
    */
    public AES(int Block_size){
        if(total_aess++<=0){
            InitVars(Block_size);
        }
    }
    
    /*
    ** Sets Mode either to Encryption or Decryption
    **
    ** @param Mode
    ** mode rither encryption or decryption
    */
    private void setMode(char Mode){
        mode=Mode;
    }

    /*
    ** Sets Total Number of rounds according to the number of block size given
    */
    private void setTotalNumOfRounds() {
        if(block_size==128)total_rounds=11;
        else if(block_size==192)total_rounds=13;
        else if(block_size==256)total_rounds=15;
        else System.out.println("Block Size is infeasible\nNumber of Rounds unidentified");
    }

    /*
    ** Properly helps setup AES algorithm
    ** Declares Rcon array
    ** Generates Round Keys
    **
    ** @param Block_sizes
    ** block size
    **
    ** @param poly
    ** given polynomial
    **
    ** @param key
    ** given key
    */
    private void initVars(int Block_sizes, int poly, String key){
        mode='e';
        block_size=Block_sizes;
        polynomial = poly;
        setTotalNumOfRounds();
        FillRcon();
        setFirstRoundKey(key);
        ComputeNextRoundKeys();
//        helper=new AESSubBytesTables();
    }
    
    /*
    ** Properly helps setup AES algorithm
    ** Declares Rcon array
    ** Generates Round Keys
    **
    ** @param Block_size
    ** size of block
    */
    private void InitVars(int Block_size) {
        mode='e';
        block_size=Block_size;
        setTotalNumOfRounds();
        FillRcon();
        SetFirstRoundKey();
        ComputeNextRoundKeys();
//        helper=new AESSubBytesTables();
    }
    
    /*
    ** The main method for encryption
    ** Takes plain text as input
    ** Outputs cipher text
    **
    ** @param pt
    ** plaintext
    **
    ** @return cipher text
    */
    private String Encryption(String pt){
        mode='e';
//        int minmax_size=block_size/4;
//        p_text = TransposeKey(p_text);
        int len=pt.length();
        if(len<=0)return "Empty Input. Input Size is 0";
        if(len>32)return "Out of Bounds Input. Greater than 32";
        if(len<32)pt+=AddPadding(len%32); //Add Padding if necessary
        pt = (AddRoundKey(pt, 0)); //First Round uses Main Key
//        System.out.println(p_text);
        for(int i=1;i<total_rounds-1;i++){ //Round is not the last one
//            p_text=(AddRoundKey(MixColumns(ShiftRows(SubBytes(p_text))), i));// Intermediate Roundss not the last one
            pt = (AddRoundKey(MixColumns(ShiftRows(subBytes(pt))), i));// Intermediate Rounds
//            System.out.println(p_text);
        }
//        return AddRoundKey((ShiftRows(SubBytes(p_text))), total_rounds-1);// Last Round
        return (AddRoundKey((ShiftRows(subBytes(pt))), total_rounds-1));// Last Round
//        return text_cipher;
    }
    
    /*
    ** The main function for Decryption
    ** Takes cipher text as input
    ** Outputs plain text
    **
    ** @param ct
    ** cipher text
    **
    ** @return palin text
    */
    private String Decryption(String ct){
        mode='d';
//        p_text=(SubBytes(ShiftRows(AddRoundKey(p_text, total_rounds-1))));// Decrypt Last Round
        ct=(subBytes(ShiftRows(AddRoundKey(ct, total_rounds-1))));// Decrypt Last Round
//        System.out.println("Decrypion = "+p_text);
        for (int i = total_rounds-2; i > 0; i--) {
//            p_text=(SubBytes(ShiftRows(MixColumns(AddRoundKey(p_text, i)))));//Decrypt Intermediate > 0; i--) {
            ct=(subBytes(ShiftRows(MixColumns(AddRoundKey(ct, i)))));//Decrypt Intermediate 
//            System.out.println("Decryption = "+p_text);
        }
        text_plain=AddRoundKey(ct, 0);// Decrypt First Round
        return text_plain;
    }
    
    /*
    ** @param temp_len
    ** takes length of a strign as input
    **
    ** @return string of 0s of sizes 32-temp_len 
    */
    private String AddPadding(int temp_len) {
        String temp="";
        int increase=32-temp_len;
        while(increase-->0){
            temp+='0';
        }
        return temp;
    }

    /*
    ** Fills Rcon array with appropriate values
    */
    private void FillRcon() {
        Rcon=new ArrayList<String>();
        if(block_size==128){
            Rcon.add("01000000");
            Rcon.add("02000000");
            Rcon.add("04000000");
            Rcon.add("08000000");
            Rcon.add("10000000");
            Rcon.add("20000000");
            Rcon.add("40000000");
            Rcon.add("80000000");
            Rcon.add("1b000000");
            Rcon.add("36000000");
            Rcon.add("108");
        }
    }
    
    /*
    **
    ** sets first round key equal to given key
    **
    ** @param key
    ** given key
    */
    private void setFirstRoundKey(String key){
        RoundKeys = new ArrayList<String>();
//        RoundKeys.add(TransposeKey(key));
        RoundKeys.add(key);
    }

    /*
    ** sets first round key equal to hardcoded key
    */
    private void SetFirstRoundKey() {
        RoundKeys=new ArrayList<String>();
//        String k="";
//        Random gen=new Random();
//        int size=block_size/8;
//        for(int i=0;i<size;i++){
//            String temp=DecTo2Hex((int)gen.nextInt(256));
//            if(temp.length()%2!=0){
//                temp+=Integer.toString(0);
//            }
//            k+=temp;
//        }
        
        String k="2b28ab097eaef7cf15d2154f16a6883c";
        k=transpose(k);
        RoundKeys.add(k);
    }
    
    /*
    ** Computes next round keys
    */
    private void ComputeNextRoundKeys() {
        for (int rk_num = 1; rk_num <= total_rounds; rk_num++) {
            String rk_cur="";
            String s = "";
            s = getKeyPart(rk_num, 1, rk_cur);
            rk_cur = rk_cur.concat(s);
//            System.out.println(rk_num+" = "+s);
            s = getKeyPart(rk_num, 2, rk_cur);
            rk_cur = rk_cur.concat(s);
//            System.out.println(rk_num+" = "+s);
            s = getKeyPart(rk_num, 3, rk_cur);
            rk_cur = rk_cur.concat(s);
//            System.out.println(rk_num+" = "+s);
            s = getKeyPart(rk_num, 4, rk_cur);
            rk_cur = rk_cur.concat(s);
//            System.out.println(rk_num+" = "+s);
//            rk_cur+=GetKey(rk_num,1,rk_cur);
//            rk_cur+=GetKey(rk_num,2,rk_cur);
//            rk_cur+=GetKey(rk_num,3,rk_cur);
//            rk_cur+=GetKey(rk_num,4,rk_cur);
//            System.out.println(rk_cur);
            RoundKeys.add(rk_cur);
        }
    }
    
    /*
    ** computes part of the round key
    **
    ** @param rk_num
    ** round key number
    ** 
    ** @param column_num
    ** column number
    ** 
    ** @param cur_key
    ** partially completed round key column
    **
    ** @return a column of round key
    */
    private String getKeyPart(int rk_num, int column_num, String cur_key){
        String s="";
        if(column_num-1==0){
//            return MyXOR(MyXOR(GetWord(rk_num-1,1), SubBytes(Shift(rk_num-1,1,4))),(String)Rcon.get(rk_num-1));
//            return MyXOR(MyXOR(GetWord(rk_num-1,1), subBytes(Shift(rk_num-1,1,4))),(String)Rcon.get(rk_num-1));
//            String r = (String)Rcon.get(rk_num-1);
//            System.out.println("r = "+r);
//            String sub = subBytes(Shift(rk_num-1,1,4));
//            System.out.println("sub = "+sub);
            return MyXOR(MyXOR(GetWord(rk_num-1,1), subBytes(Shift(rk_num-1,1,4))),(String)Rcon.get(rk_num-1));
        }
        else{
            return MyXOR(GetWord(rk_num-1, column_num), getWord(cur_key, column_num-1));
        }
//        return s;
    }
    
    /*
    ** gets a part of previously generated round keys
    **
    ** @param rk_num
    ** round key number
    **
    ** @param word
    ** column number from previous round key
    **
    ** @return column word from round key number rk_num
    */
    private String GetWord(int rk_num, int word){
        String s="";
        int end=word*8;
        String temp=(String)RoundKeys.get(rk_num);
        for (int j = 8*(word-1); j < end; j++) {
            s+=temp.charAt(j);
        }
        return s;
    }
    
    /*
    ** gets a substring
    **
    ** @param temp
    ** a string
    **
    ** @param word
    ** start position
    **
    ** @return substring temp(8*(word-1), word*8)
    */
    private String getWord(String temp, int word){
//        String s="";
//        int end=word*8;
        return temp.substring(8*(word-1), word*8);
//        for (int j = 8*(word-1); j < end; j++) {
//            s+=temp.charAt(j);
//        }
//        return temp;
    }
    
    /*
    ** Shifts a roundkey word by some rotations
    **
    ** @param rk_num
    ** round key number
    **
    ** @param rot
    ** number of times to be rotated
    **
    ** @param word
    ** part of the roundkey
    **
    ** @return
    ** rotated part of roundkey[rk_num]
    */
    private String Shift(int rk_num, int rot, int word){
        String s="";
        String temp=GetWord(rk_num, word);
        int len=temp.length();
        rot=rot*2;
        for (int j = 0, another=len+rot; j < len; j++, another++) {
            s+=temp.charAt(another%len);
        }
        return s;
    }
    
    /*
    ** Rotates strings eitehr left or right
    **
    ** @param temp
    ** String to be rotated
    **
    ** @param shift
    ** amount of rotations
    **
    ** @param LorR
    ** Direction of shifts
    **
    **  @return rotated string
    */
    private String RotateWords(String temp, int shift, char LorR){
        String s="";
        int len=temp.length();
        int another=0;
        if(LorR=='e' || LorR=='E')another=len+shift;
        else if(LorR=='d' || LorR=='D')another=3*shift;
        for (int j = 0; j < len; j++, another++) {
            s+=temp.charAt(another%len);
        }
        return s;
    }
    
    /*
    ** XORs given strings
    **
    ** @param s1
    ** string number 1
    **
    ** @param s2
    ** string number 2
    **
    ** @return XORed string
    */
    private String MyXOR(String s1, String s2){
        String s="";
        int len1=s1.length();
        int len2=s2.length();
        if(s1.length()!=len2){
            String temp="";
            for(int i=0;i<s1.length()-s2.length();i++){
                temp+="0";
            }
            temp+=s2;
            s2=temp;
        }
        for (int i = 0; i < len1; i++) {
            s+=Integer.toHexString(HexToDec(s1.charAt(i)) ^ HexToDec(s2.charAt(i)));
        }
        return s;
    }

    /*
    ** converts character from decimal to hex
    **
    ** @param gchar
    ** given character
    **
    ** @return hex value of gchar
    */
    private int HexToDec(char gchar) {
//        int ret=0;
        if(gchar>=97 && gchar<=122){
            return gchar-97+10;
        }
        else if(gchar>=65 && gchar<=90){
            return gchar-65+10;
        }
        else{
            return Integer.parseInt(Character.toString(gchar));
        }
//        return ret;
    }
    
//    private String Hex_to_bin(char c) {
//        String temp="";
//        int val=-1;
//        if(c>=97 && c<=122){
//            val=c-97+10;
//        }
//        else if(c>=65 && c<=90){
//            val=c-65+10;
//        }
//        else if(c>='0' && c<='9'){
//            val=c-'0';
//        }
//        String hex=Integer.toBinaryString(val);
//        int diff=4-hex.length();
//        while(diff>0){
//            temp+="0";
//            diff--;
//        }
//        temp+=hex;
//        return temp;
//    }
    
    /*
    ** Performs subBytes operation on the state
    **
    ** @param text
    ** given text
    **
    ** @return text on which subBytes has been performed
    */
    private String subBytes(String text){
        String result = "";
        int len = text.length();
        for (int i = 0; i < len; i+=2) {
            String temp = text.substring(i, i+2);
//            System.out.println("temp = "+temp);
            int num = Integer.parseInt(text.substring(i, i+2), 16);
            if(mode == 'e' || mode == 'E'){
                for (int j = 1; j < 65536; j++) {
                    int inverse = modMultiply(num, j, polynomial);
//                    System.out.println("j = "+j);
//                    if(num == 0){
//                        result = result.concat("63");
//                        System.out.println("temp = "+temp);
//                        break;
//                    }
                    if(inverse == 1 || num == 0){
                        int k = 0;
                        String temp2 = "";
                        if(num != 0){
                            k = Integer.parseInt(reverse(rightXOR(mulMat(Integer.toBinaryString(j)))), 2);
                        }
                        else if (num == 0){
                            k = Integer.parseInt(reverse(rightXOR("0")), 2);
                        }
                        temp2 = Integer.toHexString(k);
//                        result = result.concat(Integer.toHexString(k));
//                        if(num == 0){
//                            System.out.println("temp 2 = "+temp2);
//                        }
                        if(temp2.length()%2 == 1){
                            result = result.concat("0"+temp2);
                        }
                        else{
                            result = result.concat(temp2);
                        }
//                        System.out.println("This = "+Integer.toHexString(k));
                        break;
                    }
                }
            }
            else{
                String mulMat = mulMat(Integer.toBinaryString(num));
                String rightXOR = reverse(rightXOR(mulMat));
                if(num == 0){
//                    System.out.println("rightXor = "+rightXOR);
                    rightXOR = reverse(rightXOR("0"));
                }
                int number = Integer.parseInt(rightXOR, 2);
                for (int j = 1; j < 65536; j++) {
                    int inverse = modMultiply(j, number, polynomial);
                    if(number == 0){
                        result = result.concat("00");
//                        System.out.println("mulMat = "+mulMat);
//                        System.out.println("rightXOR = "+rightXOR);
                        break;
                    }
                    if(inverse == 1){
//                        result = result.concat(Integer.toHexString(j));
                        String temp2 = Integer.toHexString(j);
//                        result = result.concat(Integer.toHexString(k));
                        if(temp2.length()%2 == 1){
                            result = result.concat("0"+temp2);
                        }
                        else{
                            result = result.concat(temp2);
                        }
                        break;
                    }
                }
            }
        }
//        System.out.println("subByteResult = "+result);
        return result;
    }

//    private String SubBytes(String text) {
//        String temp="";
//        int mul=32;
//        int p_length=text.length();
//        for(int i=0;i<p_length;i+=2){
//            int row=GetRow(HexToDec(text.charAt(i)),mul);
//            int col=GetCol(HexToDec(text.charAt(i+1)));
//            if(mode=='e' || mode=='E'){
//                temp+=s_box.charAt(row+col);
//                temp+=s_box.charAt(row+col+1);
//            }
//            else if(mode=='d' || mode=='D'){
//                temp+=s_box_inverse.charAt(row+col);
//                temp+=s_box_inverse.charAt(row+col+1);
//            }
//        }
//        return temp;
//    }

//    private int GetRow(int r, int mul) {
//        return r*mul;
//    }
//
//    private int GetCol(int c) {
//        return c*2;
//    }

    /*
    ** Rotates a row in a state
    **
    ** @param text
    ** given string which describes a state
    **
    ** @return shifts rows in a state by hardcoded amount
    */
    private String ShiftRows(String text) {
        String s="";
        int t_length=text.length()/8;
        for (int i = 0; i < t_length; i++) {
            s=s.concat(RotateWords(GetWord(transpose(text), i*8, i*8+8), i*2, mode));
        }
//        System.out.println(s);
//        System.out.println(TransposeKey(s));
        return transpose(s);
    }
    
    
    private String GetWord(String text, int start, int end){
        return text.substring(start, end);
//        String s="";
//        for (int i = start; i < end; i++) {
//            s+=text.charAt(i);
//        }
//        return s;
    }

    private String MixColumns(String text) {
        String answer="";
        int t_length=text.length()/8;
        int m_length=mat_mixCol.length();
        for (int word_col = 0; word_col < t_length; word_col++) {
            String p_text=getWord(text,word_col+1);
            for (int mat_row = 0; mat_row < m_length; mat_row+=8) {
                if(mode=='e' || mode=='E'){
                    answer+=Multiply(GetWord(mat_mixCol, mat_row, mat_row+8), p_text);
                }
                else if(mode=='d' || mode=='D'){
                    answer+=MultiplyDecryption(GetWord(mat_mixCol_inverse, mat_row, mat_row+8), p_text);
//                    answer+=Multiply(GetWord(mat_mixCol_inverse, mat_row, mat_row+8), p_text);
                }
            }
        }
//        System.out.println(answer);
        return answer;
    }
    
    private String GetFromTable(String s1, String s2){
//        return DecTo2Hex((SelectTable(HexToDec(s1)))[HexToDec(s2)]);
        
        String ans = "";
        if(s1.length() < 2) s1 = "0" + s1;
        if(s2.length() < 2) s2 = "0" + s2;
//        
////        System.out.println("s1 = "+s1);
////        System.out.println("s2 = "+s2);
//        
//        int val1 = Integer.parseInt(s1, 16);
//        int val2 = Integer.parseInt(s2, 16);
////        ans = Integer.toBinaryString((int) multiply(val1, val2));
//        if (val1 == 2) {
//            mVal = val2;
//            ans = mul2InGf8(val2);
//        }
////        ans = Integer.toBinaryString(val2);
////        while (ans.length() < 8) ans = "0" + ans;
////        ans = ans.substring(1);
////        while(ans.length() < 8) ans = ans.concat("0");
////        System.out.println("ls = "+ans);
////        if (val2 > 127) ans = MyXOR("00011011", ans); // XOR with 1B
////        System.out.println("1B = "+ans);
//        else if(val1 == 3) {
//            mVal = val2;
//            ans = MyXOR(mul2InGf8(val2), Integer.toBinaryString(val2));
//        }
//        else if(val1 == 9) {
////            ans = mul2InGf8(val2);
//            mVal = val2;
//            ans = MyXOR(mul2InGf8(mul2InGf8(mul2InGf8(val2, val2), val2)), Integer.toBinaryString(val2));
//        }
//        else if(val1 == 11) {
//            mVal = val2;
//            ans = MyXOR(mul2InGf8(Integer.parseInt(MyXOR(mul2InGf8(mul2InGf8(val2, val2)),
//                    Integer.toBinaryString(val2)), 2))
//                    , Integer.toBinaryString(val2));
//        }
//        else if(val1 == 13) {
//            mVal = val2;
//            int mul2_1 = Integer.parseInt(mul2InGf8(val2), 2);
//            
//            ans = MyXOR(mul2InGf8(mul2InGf8(Integer.parseInt(MyXOR(mul2InGf8(val2),
//                    Integer.toBinaryString(val2)), 2)))
//                    , Integer.toBinaryString(val2));
//        }
//        else if(val1 == 14) {
//            mVal = val2;
//            ans = mul2InGf8(Integer.parseInt(MyXOR(mul2InGf8(Integer.parseInt(MyXOR(mul2InGf8(val2),
//                    Integer.toBinaryString(val2)), 2)),
//                    Integer.toBinaryString(val2)), 2));
//        }
//        val1 = Integer.parseInt(ans, 2);
//        ans = Integer.toHexString(val1);
//        if(ans.length() < 2) {
////            System.out.println("Flaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaag");
//            ans = "0" + ans;
//        }
////        System.out.println("ans = "+ans);
        
        ans = Integer.toHexString(modMultiply(Integer.parseInt(s1, 16), Integer.parseInt(s2, 16), polynomial));
        if(ans.length() < 2) ans = "0" + ans;
        return ans;
    }
    
//    private int mul2InGf8(String hex, int ret) {
//        return Integer.parseInt(mul2InGf8(hex), 2);
//    }
//    
//    private String mul2InGf8(String hex, char ret) {
//        int val = Integer.parseInt(mul2InGf8(hex), 2);
//        String ans = Integer.toHexString(val);
//        while(ans.length() < 2) ans = "0" + ans;
//        return ans;
//    }
//    
//    private String mul2InGf8(String hex) {
//        return mul2InGf8(Integer.parseInt(hex, 16));
//    }
//    
//    private String mul2InGf8(int val) {
//        String ans = "";
//        ans = Integer.toBinaryString(val);
//        while (ans.length() < 8) ans = "0" + ans;
//        ans = ans.substring(1, 8); // 1 bit left shift
//        while(ans.length() < 8) ans = ans.concat("0");
//        if (val > 127) ans = MyXOR("00011011", ans); // XOR with 1B
////        if (mVal > 127) ans = MyXOR("00011011", ans); // XOR with 1B
//        while (ans.length() < 8) ans = "0" + ans;
//        return ans;
//    }
//    
//    private int mul2InGf8(int val, int val2) {
//        return Integer.parseInt(mul2InGf8(val), 2);
//    }
    
    private String MultiplyDecryption(String row, String col){
        String ans="";
//        System.out.println("row = "+row);
//        System.out.println("col = "+col);
        int r_length=row.length();
        for (int i = 0; i < r_length; i+=2) {
            String s1=Character.toString(row.charAt(i))+Character.toString(row.charAt(i+1));
            String s2=Character.toString(col.charAt(i))+Character.toString(col.charAt(i+1));
            String xor=GetFromTable(s1, s2);
            if(i==0)ans=xor;
            else ans=MyXOR(xor, ans);
        }
        return ans;
    }
    
    private String Multiply(String row, String col){
//        System.out.println("row = "+row);
//        System.out.println("col = "+col);
        String ans="";
        int row_length=row.length();
        for (int i = 0; i < row_length; i+=2) {
            String s1=Character.toString(row.charAt(i))+Character.toString(row.charAt(i+1));
            String s2=Character.toString(col.charAt(i))+Character.toString(col.charAt(i+1));
            int val1=HexToDec(s1);
//            System.out.println("val1 = "+val1);
//            System.out.println("s1 = "+s1);
//            System.out.println("s2 = "+s1);
            String xor="";
            if(val1==1) xor=s2; // if multiplying with 1, value will be same
            else xor=GetFromTable(s1, s2);
            if(i==0) ans=xor; // no xor firsst time
            else ans=MyXOR(xor, ans); // xor in steps where i > 0
//            System.out.println("Answer = "+ans);
//            try {
//                System.in.read();
//            } catch (IOException ex) {
//                Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
//            }
        }
        return ans;
    }

    private int HexToDec(String s) {
        int val=0;
        int s_length=s.length();
        for (int i = 0, j=s_length-1; i < s_length; i++,j--) {
            val=val+(HexToDec(s.charAt(i)) * ((int)Math.pow(16, j)));
        }
        return val;
    }
    
    /*
    ** @param text
    ** plain text or cipher text block
    **
    ** @param round_num
    ** Current round number
    **
    ** @return text block with current round key added in it
    */
    private String AddRoundKey(String text, int round_num){
        String ret="";
        String key=(String)RoundKeys.get(round_num);
        for (int i = 0, j=0; j<4 ; i=j+1,j++) {
            ret+=MyXOR(GetWord(text, i*8, i*8+8), GetWord(key, i*8, i*8+8));
        }
//        System.out.println("Dec = "+ret);
//        if(mode == 'd' || mode == 'D') return ret;
//        return TransposeKey(ret);
        return ret;
    }

    /*
    ** @param text
    ** text block
    **
    ** @return transposed text block as it treats whole of the string as matrix
    */
    private String transpose(String text) {
        String ret="";
        for (int j=0; j < 4; j++) {
            for (int i = 2*j, count=1; count<5; i+=8,count++) {
                ret+=text.charAt(i);
                ret+=text.charAt(i+1);
            }
        }
        return ret;
    }

    /*
    ** @param dec
    ** decimal value
    **
    ** @return 2 digit hex
    */
    private String DecTo2Hex(int dec) {
        String k="0";
        String val=Integer.toHexString(dec);
        if(val.length()<2){
            k+=val;
            val=k;
        }
        return val;
    }

//    private int[] SelectTable(int t) {
//        if(t==2)return helper.table_2;
//        else if(t==3)return helper.table_3;
//        else if(t==9)return helper.table_9;
//        else if(t==11)return helper.table_11;
//        else if(t==13)return helper.table_13;
//        else if(t==14)return helper.table_14;
//        else return new int[]{};
//    }
    
    /*
    ** @param mulResult
    ** binary string from the output of s or inverse s box matrix multiplication
    **
    ** @return xored string
    */
    private String rightXOR(String mulResult){
        String result = "";
        String xorRight = "";
        if(mode == 'e' || mode == 'E'){
            xorRight = "11000110";
        }
        else{
            xorRight = "10100000";
        }
        mulResult = AddZeroesAtStart(mulResult, xorRight.length());
        int len = xorRight.length();
        for (int i = 0; i < len; i++) {
            if(xorRight.charAt(i) == mulResult.charAt(i)){
                result = result.concat("0");
            }
            else{
                result = result.concat("1");
            }
        }
        return result;
    }
    
    /*
    ** @param s
    ** any string with length less than max_len
    **
    ** @param max_len
    ** length of another string
    **
    ** @return string of length max_len which has 0s added in the start
    */
    private String AddZeroesAtStart(String s, int max_len){
        while(s.length() < max_len){
            s = "0" + s;
        }
        return s;
    }
    
    /*
    ** @param mul
    ** a 1*8 string matrix
    **
    ** @return s or inverse s box matrix multiplicated string
    */
    private String mulMat(String mul){
        String result = "";
        mul = AddZeroesAtStart(mul, 8);
        mul = reverse(mul);
        String mulLeft = "";
        if(mode == 'e' || mode == 'E'){
            mulLeft = "10001111";
        }
        else{
            mulLeft = "00100101";
        }
        for (int i = 0; i < 8; i++) {
            int count = 0;
            String mul_temp = "";
            for (int j = 0; j < 8; j++) {
                if(mulLeft.charAt(j) == '1' && mul.charAt(j) == '1'){
                    mul_temp = mul_temp.concat("1");
                    count++;
                }
                else{
                    mul_temp = mul_temp.concat("0");
                }
            }
            if(count % 2 == 1){
                result = result.concat("1");
            }
            else{
                result = result.concat("0");
            }
            mulLeft = rightShift(mulLeft, 1);
        }
        return result;
    }
    
    /*
    ** @param s
    ** any string
    **
    ** @param rs
    ** amount of right shifts 
    **
    ** @return string that is right shifted rs times
    */
    private String rightShift(String s, int rs){
        String temp = ""; 
        int len = s.length();
        int counter = 0;
        for (int i = (len - rs)%len; counter < len; i++, counter++) {
            temp = temp.concat(Character.toString(s.charAt(i%len)));
        }
        return temp;
    }
    
    /*
    ** @param s
    ** any string
    **
    ** @return reverse of s
    */
    private String reverse(String s) {
        int len = s.length();
        String temp = "";
        for (int i = len - 1; i >= 0; i--) {
            temp = temp.concat(Character.toString(s.charAt(i)));
        }
        return temp;
    }
    
    /*
    ** @param line
    ** binary string with spaces between 0s and 1s
    **
    ** @return bianry string with spaces removed
    */
    private static String getPolynomial(String line) {
        String temp = "";
        StringTokenizer tokens = new StringTokenizer(line);
        while (tokens.hasMoreTokens()) {  
            temp = temp.concat(tokens.nextToken()); 
        }  
//        System.out.println("Line = "+temp);
        return temp;
    }
    
    /*
    ** Writes text to file
    **
    ** @param text
    ** any text
    */
    private static void writeToFile(String text){
        try{
            PrintWriter writer = new PrintWriter("output.txt", "UTF-8");
            writer.println(text);
            writer.close();
        } catch (Exception e) {
           // do something
        }
    }
    
    /*
    ** @param fileName
    ** name of the file to read from
    **
    ** @return object strign that contains polynomial, keys, plain text and cipher text
    */
    private static Object[] readFromFile(String fileName){
                // The name of the file to open.

        // This will reference one line at a time
        String line = null;
        String polynomial = "", key = "", text_plain = "", text_cipher = "";

        try {
            // FileReader reads text files in the default encoding.
            FileReader fileReader = 
                new FileReader(fileName);

            // Always wrap FileReader in BufferedReader.
            BufferedReader bufferedReader = 
                new BufferedReader(fileReader);
            int counter = 0;
            while((line = bufferedReader.readLine()) != null) {
                if(counter == 0){
                    polynomial = getPolynomial(line);
                }
                else if(counter == 1){
                    key = line;
                }
                else if(counter == 2){
                    text_plain = line;
                }
                else if(counter == 3){
                    text_cipher = line;
                }
                
//                System.out.println(line);
                counter++;
            }   

            // Always close files.
            bufferedReader.close();         
        }
        catch(FileNotFoundException ex) {
            System.out.println(
                "Unable to open file '" + 
                fileName + "'");                
        }
        catch(IOException ex) {
            System.out.println(
                "Error reading file '" 
                + fileName + "'");                  
            // Or we could just do this: 
            // ex.printStackTrace();
        }
        return new Object[]{polynomial, key, text_plain, text_cipher};
    }
    
    /**
     * Return sum of two polynomials
     *
     * @param p polynomial
     * @param q polynomial
     * @return p+q
     */
    public static int add(int p, int q)
    {
        return p ^ q;
    }

    /**
     * Return product of two polynomials
     *
     * @param p polynomial
     * @param q polynomial
     * @return p*q
     */

    public static long multiply(int p, int q){
        long result = 0;
        if (q != 0)
        {
            long q1 = q & 0x00000000ffffffffL;

            while (p != 0)
            {
                byte b = (byte)(p & 0x01);
                if (b == 1)
                {
                    result ^= q1;
                }
                p >>>= 1;
                q1 <<= 1;

            }
        }
        return result;
    }

    /**
     * Compute the product of two polynomials modulo a third polynomial.
     *
     * @param a the first polynomial
     * @param b the second polynomial
     * @param r the reduction polynomial
     * @return <tt>a * b mod r</tt>
     */
    public static int modMultiply(int a, int b, int r)
    {
        int result = 0;
        int p = remainder(a, r);
        int q = remainder(b, r);
        if (q != 0)
        {
            int d = 1 << degree(r);

            while (p != 0)
            {
                byte pMod2 = (byte)(p & 0x01);
                if (pMod2 == 1)
                {
                    result ^= q;
                }
                p >>>= 1;
                q <<= 1;
                if (q >= d)
                {
                    q ^= r;
                }
            }
        }
        return result;
    }

    /**
     * Return the degree of a polynomial
     *
     * @param p polynomial p
     * @return degree(p)
     */

    public static int degree(int p)
    {
        int result = -1;
        while (p != 0)
        {
            result++;
            p >>>= 1;
        }
        return result;
    }

    /**
     * Return the degree of a polynomial
     *
     * @param p polynomial p
     * @return degree(p)
     */

    public static int degree(long p)
    {
        int result = 0;
        while (p != 0)
        {
            result++;
            p >>>= 1;
        }
        return result - 1;
    }

    /**
     * Return the remainder of a polynomial division of two polynomials.
     *
     * @param p dividend
     * @param q divisor
     * @return <tt>p mod q</tt>
     */
    public static int remainder(int p, int q)
    {
        int result = p;

        if (q == 0)
        {
            System.err.println("Error: to be divided by 0");
            return 0;
        }

        while (degree(result) >= degree(q))
        {
            result ^= q << (degree(result) - degree(q));
        }

        return result;
    }

    /**
     * Return the rest of division two polynomials
     *
     * @param p polynomial
     * @param q polynomial
     * @return p mod q
     */

    public static int rest(long p, int q)
    {
        long p1 = p;
        if (q == 0)
        {
            System.err.println("Error: to be divided by 0");
            return 0;
        }
        long q1 = q & 0x00000000ffffffffL;
        while ((p1 >>> 32) != 0)
        {
            p1 ^= q1 << (degree(p1) - degree(q1));
        }

        int result = (int)(p1 & 0xffffffff);
        while (degree(result) >= degree(q))
        {
            result ^= q << (degree(result) - degree(q));
        }

        return result;
    }

    /**
     * Return the greatest common divisor of two polynomials
     *
     * @param p polynomial
     * @param q polynomial
     * @return GCD(p, q)
     */

    public static int gcd(int p, int q)
    {
        int a, b, c;
        a = p;
        b = q;
        while (b != 0)
        {
            c = remainder(a, b);
            a = b;
            b = c;

        }
        return a;
    }

    /**
     * Checking polynomial for irreducibility
     *
     * @param p polynomial
     * @return true if p is irreducible and false otherwise
     */

    public static boolean isIrreducible(int p)
    {
        if (p == 0)
        {
            return false;
        }
        int d = degree(p) >>> 1;
        int u = 2;
        for (int i = 0; i < d; i++)
        {
            u = modMultiply(u, u, p);
            if (gcd(u ^ 2, p) != 1)
            {
                return false;
            }
        }
        return true;
    }

    /**
     * Creates irreducible polynomial with degree d
     *
     * @param deg polynomial degree
     * @return irreducible polynomial p
     */
    public static int getIrreduciblePolynomial(int deg)
    {
        if (deg < 0)
        {
            System.err.println("The Degree is negative");
            return 0;
        }
        if (deg > 31)
        {
            System.err.println("The Degree is more then 31");
            return 0;
        }
        if (deg == 0)
        {
            return 1;
        }
        int a = 1 << deg;
        a++;
        int b = 1 << (deg + 1);
        for (int i = a; i < b; i += 2)
        {
            if (isIrreducible(i))
            {
                return i;
            }
        }
        return 0;
    }
    
    public class AESSubBytesTables {
    
    public int table_2[]={0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
                        0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
                        0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
                        0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
                        0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
                        0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
                        0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
                        0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
                        0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
                        0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
                        0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
                        0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
                        0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
                        0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
                        0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
                        0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5};
    
    public int table_3[]={0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
                        0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
                        0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
                        0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
                        0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9,0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1,
                        0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9,0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1,
                        0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9,0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1,
                        0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99,0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81,
                        0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92,0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a,
                        0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2,0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba,
                        0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2,0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea,
                        0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2,0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda,
                        0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
                        0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
                        0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
                        0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a};
    
    public int table_9[]={0x00,0x09,0x12,0x1b,0x24,0x2d,0x36,0x3f,0x48,0x41,0x5a,0x53,0x6c,0x65,0x7e,0x77,
                        0x90,0x99,0x82,0x8b,0xb4,0xbd,0xa6,0xaf,0xd8,0xd1,0xca,0xc3,0xfc,0xf5,0xee,0xe7,
                        0x3b,0x32,0x29,0x20,0x1f,0x16,0x0d,0x04,0x73,0x7a,0x61,0x68,0x57,0x5e,0x45,0x4c,
                        0xab,0xa2,0xb9,0xb0,0x8f,0x86,0x9d,0x94,0xe3,0xea,0xf1,0xf8,0xc7,0xce,0xd5,0xdc,
                        0x76,0x7f,0x64,0x6d,0x52,0x5b,0x40,0x49,0x3e,0x37,0x2c,0x25,0x1a,0x13,0x08,0x01,
                        0xe6,0xef,0xf4,0xfd,0xc2,0xcb,0xd0,0xd9,0xae,0xa7,0xbc,0xb5,0x8a,0x83,0x98,0x91,
                        0x4d,0x44,0x5f,0x56,0x69,0x60,0x7b,0x72,0x05,0x0c,0x17,0x1e,0x21,0x28,0x33,0x3a,
                        0xdd,0xd4,0xcf,0xc6,0xf9,0xf0,0xeb,0xe2,0x95,0x9c,0x87,0x8e,0xb1,0xb8,0xa3,0xaa,
                        0xec,0xe5,0xfe,0xf7,0xc8,0xc1,0xda,0xd3,0xa4,0xad,0xb6,0xbf,0x80,0x89,0x92,0x9b,
                        0x7c,0x75,0x6e,0x67,0x58,0x51,0x4a,0x43,0x34,0x3d,0x26,0x2f,0x10,0x19,0x02,0x0b,
                        0xd7,0xde,0xc5,0xcc,0xf3,0xfa,0xe1,0xe8,0x9f,0x96,0x8d,0x84,0xbb,0xb2,0xa9,0xa0,
                        0x47,0x4e,0x55,0x5c,0x63,0x6a,0x71,0x78,0x0f,0x06,0x1d,0x14,0x2b,0x22,0x39,0x30,
                        0x9a,0x93,0x88,0x81,0xbe,0xb7,0xac,0xa5,0xd2,0xdb,0xc0,0xc9,0xf6,0xff,0xe4,0xed,
                        0x0a,0x03,0x18,0x11,0x2e,0x27,0x3c,0x35,0x42,0x4b,0x50,0x59,0x66,0x6f,0x74,0x7d,
                        0xa1,0xa8,0xb3,0xba,0x85,0x8c,0x97,0x9e,0xe9,0xe0,0xfb,0xf2,0xcd,0xc4,0xdf,0xd6,
                        0x31,0x38,0x23,0x2a,0x15,0x1c,0x07,0x0e,0x79,0x70,0x6b,0x62,0x5d,0x54,0x4f,0x46};
    
    public int table_11[]={0x00,0x0b,0x16,0x1d,0x2c,0x27,0x3a,0x31,0x58,0x53,0x4e,0x45,0x74,0x7f,0x62,0x69,
                        0xb0,0xbb,0xa6,0xad,0x9c,0x97,0x8a,0x81,0xe8,0xe3,0xfe,0xf5,0xc4,0xcf,0xd2,0xd9,
                        0x7b,0x70,0x6d,0x66,0x57,0x5c,0x41,0x4a,0x23,0x28,0x35,0x3e,0x0f,0x04,0x19,0x12,
                        0xcb,0xc0,0xdd,0xd6,0xe7,0xec,0xf1,0xfa,0x93,0x98,0x85,0x8e,0xbf,0xb4,0xa9,0xa2,
                        0xf6,0xfd,0xe0,0xeb,0xda,0xd1,0xcc,0xc7,0xae,0xa5,0xb8,0xb3,0x82,0x89,0x94,0x9f,
                        0x46,0x4d,0x50,0x5b,0x6a,0x61,0x7c,0x77,0x1e,0x15,0x08,0x03,0x32,0x39,0x24,0x2f,
                        0x8d,0x86,0x9b,0x90,0xa1,0xaa,0xb7,0xbc,0xd5,0xde,0xc3,0xc8,0xf9,0xf2,0xef,0xe4,
                        0x3d,0x36,0x2b,0x20,0x11,0x1a,0x07,0x0c,0x65,0x6e,0x73,0x78,0x49,0x42,0x5f,0x54,
                        0xf7,0xfc,0xe1,0xea,0xdb,0xd0,0xcd,0xc6,0xaf,0xa4,0xb9,0xb2,0x83,0x88,0x95,0x9e,
                        0x47,0x4c,0x51,0x5a,0x6b,0x60,0x7d,0x76,0x1f,0x14,0x09,0x02,0x33,0x38,0x25,0x2e,
                        0x8c,0x87,0x9a,0x91,0xa0,0xab,0xb6,0xbd,0xd4,0xdf,0xc2,0xc9,0xf8,0xf3,0xee,0xe5,
                        0x3c,0x37,0x2a,0x21,0x10,0x1b,0x06,0x0d,0x64,0x6f,0x72,0x79,0x48,0x43,0x5e,0x55,
                        0x01,0x0a,0x17,0x1c,0x2d,0x26,0x3b,0x30,0x59,0x52,0x4f,0x44,0x75,0x7e,0x63,0x68,
                        0xb1,0xba,0xa7,0xac,0x9d,0x96,0x8b,0x80,0xe9,0xe2,0xff,0xf4,0xc5,0xce,0xd3,0xd8,
                        0x7a,0x71,0x6c,0x67,0x56,0x5d,0x40,0x4b,0x22,0x29,0x34,0x3f,0x0e,0x05,0x18,0x13,
                        0xca,0xc1,0xdc,0xd7,0xe6,0xed,0xf0,0xfb,0x92,0x99,0x84,0x8f,0xbe,0xb5,0xa8,0xa3};    

    public int table_13[]={0x00,0x0d,0x1a,0x17,0x34,0x39,0x2e,0x23,0x68,0x65,0x72,0x7f,0x5c,0x51,0x46,0x4b,
                        0xd0,0xdd,0xca,0xc7,0xe4,0xe9,0xfe,0xf3,0xb8,0xb5,0xa2,0xaf,0x8c,0x81,0x96,0x9b,
                        0xbb,0xb6,0xa1,0xac,0x8f,0x82,0x95,0x98,0xd3,0xde,0xc9,0xc4,0xe7,0xea,0xfd,0xf0,
                        0x6b,0x66,0x71,0x7c,0x5f,0x52,0x45,0x48,0x03,0x0e,0x19,0x14,0x37,0x3a,0x2d,0x20,
                        0x6d,0x60,0x77,0x7a,0x59,0x54,0x43,0x4e,0x05,0x08,0x1f,0x12,0x31,0x3c,0x2b,0x26,
                        0xbd,0xb0,0xa7,0xaa,0x89,0x84,0x93,0x9e,0xd5,0xd8,0xcf,0xc2,0xe1,0xec,0xfb,0xf6,
                        0xd6,0xdb,0xcc,0xc1,0xe2,0xef,0xf8,0xf5,0xbe,0xb3,0xa4,0xa9,0x8a,0x87,0x90,0x9d,
                        0x06,0x0b,0x1c,0x11,0x32,0x3f,0x28,0x25,0x6e,0x63,0x74,0x79,0x5a,0x57,0x40,0x4d,
                        0xda,0xd7,0xc0,0xcd,0xee,0xe3,0xf4,0xf9,0xb2,0xbf,0xa8,0xa5,0x86,0x8b,0x9c,0x91,
                        0x0a,0x07,0x10,0x1d,0x3e,0x33,0x24,0x29,0x62,0x6f,0x78,0x75,0x56,0x5b,0x4c,0x41,
                        0x61,0x6c,0x7b,0x76,0x55,0x58,0x4f,0x42,0x09,0x04,0x13,0x1e,0x3d,0x30,0x27,0x2a,
                        0xb1,0xbc,0xab,0xa6,0x85,0x88,0x9f,0x92,0xd9,0xd4,0xc3,0xce,0xed,0xe0,0xf7,0xfa,
                        0xb7,0xba,0xad,0xa0,0x83,0x8e,0x99,0x94,0xdf,0xd2,0xc5,0xc8,0xeb,0xe6,0xf1,0xfc,
                        0x67,0x6a,0x7d,0x70,0x53,0x5e,0x49,0x44,0x0f,0x02,0x15,0x18,0x3b,0x36,0x21,0x2c,
                        0x0c,0x01,0x16,0x1b,0x38,0x35,0x22,0x2f,0x64,0x69,0x7e,0x73,0x50,0x5d,0x4a,0x47,
                        0xdc,0xd1,0xc6,0xcb,0xe8,0xe5,0xf2,0xff,0xb4,0xb9,0xae,0xa3,0x80,0x8d,0x9a,0x97};
    
    public int table_14[]={0x00,0x0e,0x1c,0x12,0x38,0x36,0x24,0x2a,0x70,0x7e,0x6c,0x62,0x48,0x46,0x54,0x5a,
                        0xe0,0xee,0xfc,0xf2,0xd8,0xd6,0xc4,0xca,0x90,0x9e,0x8c,0x82,0xa8,0xa6,0xb4,0xba,
                        0xdb,0xd5,0xc7,0xc9,0xe3,0xed,0xff,0xf1,0xab,0xa5,0xb7,0xb9,0x93,0x9d,0x8f,0x81,
                        0x3b,0x35,0x27,0x29,0x03,0x0d,0x1f,0x11,0x4b,0x45,0x57,0x59,0x73,0x7d,0x6f,0x61,
                        0xad,0xa3,0xb1,0xbf,0x95,0x9b,0x89,0x87,0xdd,0xd3,0xc1,0xcf,0xe5,0xeb,0xf9,0xf7,
                        0x4d,0x43,0x51,0x5f,0x75,0x7b,0x69,0x67,0x3d,0x33,0x21,0x2f,0x05,0x0b,0x19,0x17,
                        0x76,0x78,0x6a,0x64,0x4e,0x40,0x52,0x5c,0x06,0x08,0x1a,0x14,0x3e,0x30,0x22,0x2c,
                        0x96,0x98,0x8a,0x84,0xae,0xa0,0xb2,0xbc,0xe6,0xe8,0xfa,0xf4,0xde,0xd0,0xc2,0xcc,
                        0x41,0x4f,0x5d,0x53,0x79,0x77,0x65,0x6b,0x31,0x3f,0x2d,0x23,0x09,0x07,0x15,0x1b,
                        0xa1,0xaf,0xbd,0xb3,0x99,0x97,0x85,0x8b,0xd1,0xdf,0xcd,0xc3,0xe9,0xe7,0xf5,0xfb,
                        0x9a,0x94,0x86,0x88,0xa2,0xac,0xbe,0xb0,0xea,0xe4,0xf6,0xf8,0xd2,0xdc,0xce,0xc0,
                        0x7a,0x74,0x66,0x68,0x42,0x4c,0x5e,0x50,0x0a,0x04,0x16,0x18,0x32,0x3c,0x2e,0x20,
                        0xec,0xe2,0xf0,0xfe,0xd4,0xda,0xc8,0xc6,0x9c,0x92,0x80,0x8e,0xa4,0xaa,0xb8,0xb6,
                        0x0c,0x02,0x10,0x1e,0x34,0x3a,0x28,0x26,0x7c,0x72,0x60,0x6e,0x44,0x4a,0x58,0x56,
                        0x37,0x39,0x2b,0x25,0x0f,0x01,0x13,0x1d,0x47,0x49,0x5b,0x55,0x7f,0x71,0x63,0x6d,
                        0xd7,0xd9,0xcb,0xc5,0xef,0xe1,0xf3,0xfd,0xa7,0xa9,0xbb,0xb5,0x9f,0x91,0x83,0x8d};
    
    }
}
