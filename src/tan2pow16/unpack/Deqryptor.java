package tan2pow16.unpack;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.util.LinkedHashMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
/**
 * Copyright (c) 2019, tan2pow16. All rights reserved.
 *   License: BSD License 2.0
 */
public class Deqryptor
{
	private final ZipFile zipfile;

	public Deqryptor(String sample_jar_path, String key_AES_hex, String encrypted_entry_path, String output_dir) throws Exception
	{
		this.zipfile = new ZipFile(sample_jar_path);
		this.decryptHeaderClass(key_AES_hex, encrypted_entry_path, String.format("%s/Header.class", output_dir));
		this.zipfile.close();
	}
	
	public Deqryptor(String sample_jar_path, String[] encrypted_entry_paths, int[] data_byteArray_sizes, String key1, String key2, String output_dir) throws Exception
	{
		this.zipfile = new ZipFile(sample_jar_path);
		this.decryptStub(sample_jar_path, encrypted_entry_paths, data_byteArray_sizes, key1, key2, output_dir);
		this.zipfile.close();
	}

	private void decryptHeaderClass(String key_AES_hex, String encrypted_entry_path, String output_path) throws Exception
	{
		FileOutputStream fos = new FileOutputStream(output_path);
		fos.write(decrypt_AES(DatatypeConverter.parseHexBinary(key_AES_hex), readFromInputStream(getFromZip(this.zipfile, encrypted_entry_path))));
		fos.close();
	}
	
	private void decryptStub(String sample_jar_path, String[] encrypted_entry_paths, int[] data_byteArray_sizes, String key1, String key2, String output_dir) throws Exception
	{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(this.decrypt(encrypted_entry_paths, data_byteArray_sizes, key1, key2));
		baos.close();
		
		byte[] cache = baos.toByteArray();
		
		FileOutputStream fos = new FileOutputStream(String.format("%s/EntriesInfo.ser", output_dir));
		fos.write(cache);
		fos.close();
		
		ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(cache));
		@SuppressWarnings("unchecked")
		LinkedHashMap<String, Object[]> map = (LinkedHashMap<String, Object[]>) ois.readObject();
		ois.close();

		ZipEntry ze;
		ZipOutputStream zos;
		ZipOutputStream zos1 = new ZipOutputStream(new FileOutputStream(String.format("%s/unpacked_stub_jar.malware", output_dir)));
		ZipOutputStream zos2 = new ZipOutputStream(new FileOutputStream(String.format("%s/unpacked_bootstrap_jar.malware", output_dir)));
		for(String str : map.keySet())
		{
			System.out.println(str);
			Object[] objs = map.get(str);
			encrypted_entry_paths = (String[])objs[0];
			int[] sizes = (int[]) objs[1];
			
			System.out.println(String.format("| -> String[%d]", encrypted_entry_paths.length));
			for(String str2 : encrypted_entry_paths)
			{
				System.out.println(String.format("|    | -> %s", str2));
			}
			
			System.out.println(String.format("| -> int[%d]", sizes.length));
			for(int i : sizes)
			{
				System.out.println(String.format("|    | -> 0x%08X", i));
			}
			
			key1 = (String)objs[2];
			key2 = (String)objs[3];
			
			System.out.println(String.format("| -> %s", key1));
			System.out.println(String.format("| -> %s", key2));
			
			System.out.println("--------------------------------");

			if(str.startsWith("obfuscated/"))
			{
				zos = zos1;
				ze = new ZipEntry(str.replaceFirst("obfuscated/", ""));
			}
			else
			{
				zos = zos2;
				ze = new ZipEntry(String.format("%s.class", str.replaceFirst("bootstrap/", "").replaceAll("\\.", "/")));
			}
			ze.setTime(0);
			zos.putNextEntry(ze);
			zos.write(this.decrypt(encrypted_entry_paths, sizes, key1, key2));
			zos.closeEntry();
		}
		zos1.close();
		zos2.close();
	}
	
	public byte[] decrypt(String[] sArr, int[] iArr, String str1, String str2) throws Exception
	{
		byte[] bArr2 = str2.getBytes();
		byte[] bArr3 = new byte[1024];
		byte[] bArr4 = new byte[iArr[1]];

		int i = 0;
		for(String str3 : sArr)
		{
			InputStream is = getFromZip(this.zipfile, str3);
			int j;
			while((j = is.read(bArr3)) >= 0)
			{
				System.arraycopy(bArr3, 0, bArr4, i, j);
				i += j;
			}
		}

		PBEKeySpec keySpec0 = new PBEKeySpec(str1.toCharArray(), bArr2, 10000, 128);
		byte[] bArr1 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(keySpec0).getEncoded();
		return decrypt_AES(bArr1, bArr4);
	}
	
	private static byte[] decrypt_AES(byte[] key, byte[] data) throws Exception
	{
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
		return cipher.doFinal(data);
	}

	private static InputStream getFromZip(ZipFile zf, String name) throws Exception
	{
		while(name.startsWith("/"))
		{
			name = name.substring(1);
		}
		ZipEntry ze = zf.getEntry(name);
		return ze == null ? null : zf.getInputStream(ze);
	}
	
	private static byte[] readFromInputStream(InputStream is) throws Exception
	{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		int len = -1;
		byte[] cache = new byte[4096];
		while((len = is.read(cache)) > -1)
		{
			baos.write(cache, 0, len);
		}
		baos.close();
		is.close();
		return baos.toByteArray();
	}
	
	public static void main(String[] args) throws Exception
	{
		System.out.println("Copyright (c) 2019, tan2pow16. All rights reserved.");
		System.out.println("  License: BSD License 2.0");
		System.out.println();
		
		int mode = 0;
		try
		{
			mode = Integer.parseInt(args[0]);
		}
		catch(Exception e)
		{
			System.out.println("Usage: [mode] <input_jar_path> [mode_args ... ] <output_dir>");
			System.out.println("  For mode == 1, mode_args should be:");
			System.out.println("    <AES_key_hex> <encrypted_entry_path>");
			System.out.println("  For mode == 1, mode_args should be:");
			System.out.println("    [count] [encrypted_header_paths ... (x count)] <decrypted_item_size> <encrypted_item_size> <key1> <key2> <output_dir>");
		}

		if(mode == 1)
		{
			new Deqryptor(args[1], args[2], args[3], args[4]);
		}
		else if(mode == 2)
		{
			int encrypted_paths_count = Integer.parseInt(args[2]);
			String[] encrypted_paths = new String[encrypted_paths_count];
			for(int i = 0 ; i < encrypted_paths_count ; i++)
			{
				encrypted_paths[i] = args[i + 3];
			}
			int cache = encrypted_paths_count + 3;
			new Deqryptor(args[1], encrypted_paths, new int[]{Integer.parseInt(args[cache]), Integer.parseInt(args[cache + 1])}, args[cache + 2], args[cache + 3], args[cache + 4]);
		}
	}
}
