package com.dental.util;

import java.io.*;
import java.nio.file.*;

import org.springframework.core.io.ClassPathResource;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import org.json.JSONObject;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

public class UploadFile {
    private static final String CLOUDINARY_UPLOAD_URL = "https://api.cloudinary.com/v1_1/dck2nnfja/upload";
    private static final String CLOUDINARY_API_KEY = "337676999889211";
    private static final String CLOUDINARY_API_SECRET = "8A3jF8gTMLuj8PNUVu5VMZfOcNE";
    private static final String CLOUDINARY_CLOUD_NAME = "dck2nnfja";

    public static String getFileName(MultipartFile multipartFile) {
        return System.currentTimeMillis() + "-" + StringUtils.cleanPath(multipartFile.getOriginalFilename());
    }

//    public static void saveFile(String fileName, MultipartFile multipartFile) throws IOException {
//        File saveFile = new ClassPathResource("static/assets/uploads").getFile();
//        Path path = Paths.get(saveFile.getAbsolutePath()+File.separator+fileName);
//
//        try (InputStream inputStream = multipartFile.getInputStream()) {
//            Files.copy(inputStream, path, StandardCopyOption.REPLACE_EXISTING);
//        } catch (IOException ioe) {
//            throw new IOException("Could not save image file: " + fileName, ioe);
//        }
//    }

    public static String saveFile(MultipartFile multipartFile) throws IOException {
        MultiValueMap<String, Object> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("file", multipartFile.getResource());
        requestBody.add("upload_preset", "gaxpeofu");
        requestBody.add("api_key", "337676999889211");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        headers.setBasicAuth(CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET);

        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(requestBody, headers);
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> responseEntity = restTemplate.exchange(
                CLOUDINARY_UPLOAD_URL,
                HttpMethod.POST,
                requestEntity,
                String.class
        );
        System.out.println(responseEntity);
        if (responseEntity.getStatusCode() == HttpStatus.OK) {
            // Handle the successful response
            String responseBody = responseEntity.getBody();
            JSONObject jsonResponse = new JSONObject(responseBody);
            String imageUrl = jsonResponse.getString("secure_url");
            return imageUrl;
            // Process the response as needed
        } else {
            // Handle the unsuccessful response
            String errorMessage = "Failed to upload image file";
            throw new IOException(errorMessage);
        }
    }
}
