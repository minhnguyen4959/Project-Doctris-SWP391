//package util;
//
//import lombok.Data;
//
//import javax.mail.*;
//import javax.mail.internet.*;
//import java.util.Properties;
//
//@Data
//public class SendMail {
//    boolean status;
//    String defaupass;
//
//    public SendMail() {
////        status : false thì sẽ ko gửi maill
////        code xác minh là defaupass
//        this.status = false;
//        this.defaupass = "101010";
//    }
//
//
//    public static void SendMail(String to, String sub,
//                                String msg, final String user, final String pass) {
//
//        Properties props = new Properties();
//        props.put("mail.smtp.host", "smtp.gmail.com");
//        props.put("mail.smtp.port", "587");
//        props.put("mail.smtp.ssl.protocols", "TLSv1.2");
//        props.put("mail.smtp.auth", "true");
//        props.put("mail.smtp.starttls.enable", "true");
//        Session session = Session.getInstance(props, new javax.mail.Authenticator() {
//            @Override
//            protected PasswordAuthentication getPasswordAuthentication() {
//                return new PasswordAuthentication(user, pass);
//            }
//        });
//
//
//        try {
//            MimeMessage message = new MimeMessage(session);
//            message.setFrom(new InternetAddress(user));
//            message.addRecipient(Message.RecipientType.TO, new InternetAddress(to));
//            message.setSubject(sub);
//            message.setContent(msg, "text/html");
//            Transport.send(message);
//        } catch (MessagingException e) {
//            e.printStackTrace();
//        }
//    }
//
//    public void sendFuncition(String to, String sub, String msg) {
//        SendMail.SendMail(to, sub, msg, "testerhe141360@gmail.com", "mwjwhrabtqvwpyvd");
//    }
//    }
//
//
