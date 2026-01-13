package com.ride.authservice.event;


public interface EventHandler<T extends BaseEvent> {
    void handle(T event);
    boolean canHandle(BaseEvent event);
    int getPriority();
}
