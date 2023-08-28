package osssanitizer.astgen_java.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import com.google.protobuf.TextFormat;


public class ProtoBufferUtil {

	/**
	 * Save Message to file.
	 * 
	 * @param msg
	 * @param msgFile
	 * @param binary
	 * @throws IOException
	 */
	public static void saveMessage(Message msg, File msgFile, boolean binary) throws IOException {
		if (binary) {
			FileOutputStream fileOutputStream;
			fileOutputStream = new FileOutputStream(msgFile);
			msg.writeTo(fileOutputStream);
			fileOutputStream.close();
		} else {
			FileWriter fileWriter = new FileWriter(msgFile);
			TextFormat.print(msg, fileWriter);
			fileWriter.close();
		}
	}

	/**
	 * Load Message from file.
	 * 
	 * @param type
	 * @param msgFile
	 * @param binary
	 * @return the loaded message
	 * @throws IOException
	 */
	public static Message loadFromFile(Message type, File msgFile, boolean binary) throws IOException {
		Message.Builder mb = type.newBuilderForType();
		if (binary) {
			FileInputStream fileInputStream;
			fileInputStream = new FileInputStream(msgFile);
			mb.mergeFrom(fileInputStream);
			fileInputStream.close();
		} else {
			FileReader fileReader = new FileReader(msgFile);
			TextFormat.merge(fileReader, mb);
			fileReader.close();
		}
		return mb.build();
	}

	/**
	 * Serialize the first message and convert it into the second type. The user is responsible for the compatibility.
	 * @param a
	 * @param b
	 * @return message a converted into b's format
	 * @throws InvalidProtocolBufferException
	 */
	public static Message serializeAtoB(Message a, Message b) throws InvalidProtocolBufferException {
		byte[] aStr = a.toByteArray();
		return b.getParserForType().parseFrom(aStr);
	}

}