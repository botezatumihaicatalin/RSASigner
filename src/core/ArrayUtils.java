package core;

public class ArrayUtils {

    public static <T> T[] concat(T[]... arrays) {

        int totalLength = 0;
        for (int i = 0, l = arrays.length; i < l; i++) {
            totalLength += arrays[i].length;
        }

        Object[] output = new Object[totalLength];

        int currentPos = 0;
        for (int i = 0, l = arrays.length; i < l; i++) {
            T[] array = arrays[i];
            System.arraycopy(array, 0, output, currentPos, array.length);
            currentPos += array.length;
        }

        return (T[]) output;
    }

    public static byte[] concat(byte[]... arrays) {

        int totalLength = 0;
        for (int i = 0, l = arrays.length; i < l; i++) {
            totalLength += arrays[i].length;
        }

        byte[] output = new byte[totalLength];

        int currentPos = 0;
        for (int i = 0, l = arrays.length; i < l; i++) {
            byte[] array = arrays[i];
            System.arraycopy(array, 0, output, currentPos, array.length);
            currentPos += array.length;
        }

        return output;
    }
}
