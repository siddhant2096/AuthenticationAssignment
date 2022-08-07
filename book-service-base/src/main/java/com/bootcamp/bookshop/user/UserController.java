package com.bootcamp.bookshop.user;

import com.bootcamp.bookshop.user.tokenAuth.AuthenticationRequest;
import com.bootcamp.bookshop.user.tokenAuth.AuthenticationResponse;
import com.bootcamp.bookshop.user.tokenAuth.JwUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {
    @Autowired
    private UserService userService;

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwUtils jwtTokenUtil;

    @PostMapping
    ResponseEntity<?> create(@RequestBody CreateUserRequest userRequest) throws InvalidEmailException {
        userService.create(userRequest);
        return ResponseEntity.ok(HttpStatus.CREATED);
    }

    @PatchMapping("/{id}")
    ResponseEntity<Object> update(@PathVariable Long id, @RequestBody UpdateUserRequest updateUserRequest) throws UserNotFoundException {
        userService.update(id, updateUserRequest);
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/authenticate")
     public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception{
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword()));
        }
        catch (BadCredentialsException ex){
            throw new Exception("incorrect username " + ex);
        }

        final UserDetails userDetails = userService.loadUserByUsername(authenticationRequest.getUsername());
        final String jwt = jwtTokenUtil.generateToken(userDetails);

        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }
}
