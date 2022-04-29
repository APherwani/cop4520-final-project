import java.io.*;
public class create_file {
    public static void main (String[] args) throws FileNotFoundException  {
        String path = args[1];
        File f = new File(path);
        PrintWriter out = new PrintWriter(f);
        for (int i = 0; i < Long.parseLong(args[0]); i++) {
            out.print(0);
        }
        out.flush();
    }
}